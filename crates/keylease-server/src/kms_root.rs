//! Where the KMS root key comes from. The root key (32 bytes) wraps every
//! Managed project's data keys. It can be:
//!
//! - `file`: a mode-0600 file with the key in unpadded base64
//!   (`KEYLEASE_KMS_ROOT_KEY_FILE`);
//! - `aws`: wrapped by AWS KMS (`Encrypt`/`Decrypt`, SigV4);
//! - `gcp`: wrapped by Google Cloud KMS;
//! - `pkcs11`: wrapped by an AES key inside a hardware security module
//!   (build with the `pkcs11` feature).
//!
//! With a wrapping provider the server keeps only the wrapped key on disk
//! (`KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE`, base64) and unwraps it once at
//! start; the plaintext key exists only in memory. `keylease-server kms init`
//! makes a new root key and writes it wrapped; `kms wrap FILE` wraps an
//! existing file key (to move from `file` to a provider).

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Associated data for the PKCS#11 AES-GCM wrapping.
#[cfg(feature = "pkcs11")]
const PKCS11_AAD: &[u8] = b"keylease-root-key-v1";

/// AWS KMS settings.
#[derive(Debug, Clone, Default)]
pub struct AwsKms {
    pub region: String,
    /// Key ID or ARN; needed to wrap, optional to unwrap.
    pub key_id: Option<String>,
    /// Instead of `https://kms.REGION.amazonaws.com` (VPC endpoints, tests).
    pub endpoint: Option<String>,
    /// Credentials; read from the environment, ECS or EC2 when absent.
    pub credentials: Option<AwsCredentials>,
}

#[derive(Clone, Default)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Google Cloud KMS settings.
#[derive(Debug, Clone, Default)]
pub struct GcpKms {
    /// `projects/P/locations/L/keyRings/R/cryptoKeys/K`.
    pub key: String,
    /// Instead of `https://cloudkms.googleapis.com` (tests).
    pub endpoint: Option<String>,
    /// A service account key file (`GOOGLE_APPLICATION_CREDENTIALS`); without
    /// it the metadata server gives the token.
    pub credentials_file: Option<PathBuf>,
    /// The metadata server (`GCE_METADATA_HOST`, default
    /// `metadata.google.internal`).
    pub metadata_host: Option<String>,
}

/// A PKCS#11 token and the AES key on it.
#[derive(Debug, Clone, Default)]
pub struct Pkcs11Kms {
    /// The vendor's PKCS#11 library (`.so`).
    pub module: PathBuf,
    pub token_label: String,
    pub pin: Zeroizing<String>,
    pub key_label: String,
}

#[derive(Debug, Clone)]
pub enum RootKeyProvider {
    File(PathBuf),
    Aws(AwsKms),
    Gcp(GcpKms),
    Pkcs11(Pkcs11Kms),
}

/// The provider and, for wrapping providers, the wrapped key file.
#[derive(Debug, Clone)]
pub struct KmsSettings {
    pub provider: RootKeyProvider,
    pub wrapped_file: Option<PathBuf>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Reads the KMS settings from the environment. `None`: no root key, so
/// Managed projects are off.
pub fn settings_from_env() -> Result<Option<KmsSettings>> {
    let provider = env("KEYLEASE_KMS_PROVIDER").unwrap_or_else(|| {
        if env("KEYLEASE_KMS_ROOT_KEY_FILE").is_some() {
            "file".into()
        } else {
            String::new()
        }
    });
    let wrapped_file = env("KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE").map(PathBuf::from);
    let provider =
        match provider.as_str() {
            "" => return Ok(None),
            "file" => RootKeyProvider::File(
                env("KEYLEASE_KMS_ROOT_KEY_FILE")
                    .context("KEYLEASE_KMS_PROVIDER=file needs KEYLEASE_KMS_ROOT_KEY_FILE")?
                    .into(),
            ),
            "aws" => RootKeyProvider::Aws(AwsKms {
                region: env("AWS_REGION")
                    .or_else(|| env("AWS_DEFAULT_REGION"))
                    .context("KEYLEASE_KMS_PROVIDER=aws needs AWS_REGION")?,
                key_id: env("KEYLEASE_AWS_KMS_KEY_ID"),
                endpoint: env("KEYLEASE_AWS_KMS_ENDPOINT"),
                credentials: None,
            }),
            "gcp" => RootKeyProvider::Gcp(GcpKms {
                key: env("KEYLEASE_GCP_KMS_KEY")
                    .context("KEYLEASE_KMS_PROVIDER=gcp needs KEYLEASE_GCP_KMS_KEY")?,
                endpoint: env("KEYLEASE_GCP_KMS_ENDPOINT"),
                credentials_file: env("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from),
                metadata_host: env("GCE_METADATA_HOST"),
            }),
            "pkcs11" => RootKeyProvider::Pkcs11(Pkcs11Kms {
                module: env("KEYLEASE_PKCS11_MODULE")
                    .context("KEYLEASE_KMS_PROVIDER=pkcs11 needs KEYLEASE_PKCS11_MODULE")?
                    .into(),
                token_label: env("KEYLEASE_PKCS11_TOKEN_LABEL")
                    .context("KEYLEASE_KMS_PROVIDER=pkcs11 needs KEYLEASE_PKCS11_TOKEN_LABEL")?,
                pin: Zeroizing::new(
                    read_text_file(
                        Path::new(&env("KEYLEASE_PKCS11_PIN_FILE").context(
                            "KEYLEASE_KMS_PROVIDER=pkcs11 needs KEYLEASE_PKCS11_PIN_FILE",
                        )?),
                        1024,
                    )?
                    .trim()
                    .to_owned(),
                ),
                key_label: env("KEYLEASE_PKCS11_KEY_LABEL")
                    .context("KEYLEASE_KMS_PROVIDER=pkcs11 needs KEYLEASE_PKCS11_KEY_LABEL")?,
            }),
            other => bail!("unknown KEYLEASE_KMS_PROVIDER {other} (file, aws, gcp or pkcs11)"),
        };
    if !matches!(provider, RootKeyProvider::File(_)) && wrapped_file.is_none() {
        bail!("a KMS provider needs KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE");
    }
    Ok(Some(KmsSettings {
        provider,
        wrapped_file,
    }))
}

/// A small regular file that only its owner can read.
fn read_text_file(path: &Path, maximum: u64) -> Result<Zeroizing<String>> {
    let metadata = std::fs::metadata(path).with_context(|| format!("read {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("{} must not be group/world accessible", path.display())
        }
    }
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("{} must be a small regular file", path.display())
    }
    Ok(Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    ))
}

/// Reads a file root key (unpadded base64 of 32 bytes).
pub fn read_root_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = read_text_file(path, 1024)?;
    let decoded = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(encoded.trim())
            .context("the root key file must be unpadded base64")?,
    );
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the root key must decode to exactly 32 bytes"))?;
    Ok(Zeroizing::new(key))
}

fn to_root_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("the unwrapped root key is not 32 bytes"))?;
    Ok(Zeroizing::new(key))
}

/// The root key, unwrapped with the configured provider.
pub async fn load_root_key(settings: &KmsSettings) -> Result<Zeroizing<[u8; 32]>> {
    let wrapped = || -> Result<Vec<u8>> {
        let path = settings
            .wrapped_file
            .as_ref()
            .context("KEYLEASE_KMS_WRAPPED_ROOT_KEY_FILE is not set")?;
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        STANDARD
            .decode(text.trim())
            .context("the wrapped root key file must be base64")
    };
    match &settings.provider {
        RootKeyProvider::File(path) => read_root_key_file(path),
        RootKeyProvider::Aws(aws) => to_root_key(&aws_decrypt(aws, &wrapped()?).await?),
        RootKeyProvider::Gcp(gcp) => to_root_key(&gcp_crypt(gcp, "decrypt", &wrapped()?).await?),
        RootKeyProvider::Pkcs11(pkcs11) => {
            let pkcs11 = pkcs11.clone();
            let wrapped = wrapped()?;
            let plain = tokio::task::spawn_blocking(move || pkcs11_crypt(&pkcs11, false, &wrapped))
                .await
                .context("the PKCS#11 task failed")??;
            to_root_key(&plain)
        }
    }
}

/// Wraps `key` with the provider; returns the base64 to store.
pub async fn wrap_root_key(settings: &KmsSettings, key: &[u8; 32]) -> Result<String> {
    let wrapped = match &settings.provider {
        RootKeyProvider::File(_) => {
            bail!("the file provider does not wrap; choose aws, gcp or pkcs11")
        }
        RootKeyProvider::Aws(aws) => aws_encrypt(aws, key).await?,
        RootKeyProvider::Gcp(gcp) => gcp_crypt(gcp, "encrypt", key).await?.to_vec(),
        RootKeyProvider::Pkcs11(pkcs11) => {
            let pkcs11 = pkcs11.clone();
            let key = Zeroizing::new(*key);
            tokio::task::spawn_blocking(move || pkcs11_crypt(&pkcs11, true, key.as_slice()))
                .await
                .context("the PKCS#11 task failed")??
                .to_vec()
        }
    };
    Ok(STANDARD.encode(wrapped))
}

/// A short fingerprint of a root key, to compare deployments without
/// showing the key.
pub fn fingerprint(key: &[u8; 32]) -> String {
    Sha256::digest([b"keylease-root-key-fingerprint-v1".as_slice(), key].concat())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build the HTTP client")
}

// ---------------------------------------------------------------------------
// AWS KMS
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// AWS Signature Version 4: the `Authorization` header. `headers` are
/// lower-case names with their values and must include `host` and
/// `x-amz-date`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sigv4_authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
    credentials: &AwsCredentials,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let mut sorted: Vec<(&str, &str)> = headers.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_headers: String = sorted
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers = sorted
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        hex(&Sha256::digest(payload))
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let key = Zeroizing::new(format!("AWS4{}", credentials.secret_access_key.as_str()));
    let k_date = hmac(key.as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        credentials.access_key_id
    )
}

/// Credentials from the environment, ECS task roles or EC2 instance roles.
async fn aws_credentials(aws: &AwsKms) -> Result<AwsCredentials> {
    if let Some(credentials) = &aws.credentials {
        return Ok(credentials.clone());
    }
    if let (Some(id), Some(secret)) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
        return Ok(AwsCredentials {
            access_key_id: id,
            secret_access_key: Zeroizing::new(secret),
            session_token: env("AWS_SESSION_TOKEN").map(Zeroizing::new),
        });
    }
    let client = http()?;
    let from_json = |value: Value| -> Result<AwsCredentials> {
        Ok(AwsCredentials {
            access_key_id: value["AccessKeyId"]
                .as_str()
                .context("no AccessKeyId")?
                .to_owned(),
            secret_access_key: Zeroizing::new(
                value["SecretAccessKey"]
                    .as_str()
                    .context("no SecretAccessKey")?
                    .to_owned(),
            ),
            session_token: value["Token"]
                .as_str()
                .map(|token| Zeroizing::new(token.to_owned())),
        })
    };
    // ECS task role.
    let ecs = env("AWS_CONTAINER_CREDENTIALS_FULL_URI").or_else(|| {
        env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            .map(|uri| format!("http://169.254.170.2{uri}"))
    });
    if let Some(uri) = ecs {
        let mut request = client.get(uri);
        if let Some(token) = env("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
            request = request.header("authorization", token);
        }
        return from_json(request.send().await?.error_for_status()?.json().await?);
    }
    // EC2 instance role (IMDSv2).
    let imds = "http://169.254.169.254/latest";
    let token = client
        .put(format!("{imds}/api/token"))
        .header("x-aws-ec2-metadata-token-ttl-seconds", "300")
        .send()
        .await
        .context("no AWS credentials in the environment and no instance metadata")?
        .error_for_status()?
        .text()
        .await?;
    let role = client
        .get(format!("{imds}/meta-data/iam/security-credentials/"))
        .header("x-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let role = role
        .lines()
        .next()
        .context("the instance has no IAM role")?;
    from_json(
        client
            .get(format!("{imds}/meta-data/iam/security-credentials/{role}"))
            .header("x-aws-ec2-metadata-token", &token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?,
    )
}

async fn aws_call(aws: &AwsKms, target: &str, body: Value) -> Result<Value> {
    let credentials = aws_credentials(aws).await?;
    let endpoint = aws
        .endpoint
        .clone()
        .unwrap_or_else(|| format!("https://kms.{}.amazonaws.com", aws.region));
    let url = url::Url::parse(&endpoint).context("invalid AWS KMS endpoint")?;
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    let payload = serde_json::to_vec(&body)?;
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let target = format!("TrentService.{target}");
    let mut headers = vec![
        ("content-type", "application/x-amz-json-1.1"),
        ("host", host.as_str()),
        ("x-amz-date", amz_date.as_str()),
        ("x-amz-target", target.as_str()),
    ];
    if let Some(token) = &credentials.session_token {
        headers.push(("x-amz-security-token", token.as_str()));
    }
    let authorization = sigv4_authorization(
        "POST",
        "/",
        "",
        &headers,
        &payload,
        &credentials,
        &aws.region,
        "kms",
        &amz_date,
    );
    let mut request = http()?.post(url).header("authorization", authorization);
    for (name, value) in headers.iter().filter(|(name, _)| *name != "host") {
        request = request.header(*name, *value);
    }
    let response = request
        .body(payload)
        .send()
        .await
        .context("reach AWS KMS")?;
    let status = response.status();
    let answer: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!(
            "AWS KMS {target} failed ({status}): {}",
            answer["__type"]
                .as_str()
                .or(answer["message"].as_str())
                .unwrap_or("error")
        );
    }
    Ok(answer)
}

async fn aws_encrypt(aws: &AwsKms, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_id = aws
        .key_id
        .as_deref()
        .context("wrapping needs KEYLEASE_AWS_KMS_KEY_ID")?;
    let answer = aws_call(
        aws,
        "Encrypt",
        json!({"KeyId": key_id, "Plaintext": STANDARD.encode(plaintext)}),
    )
    .await?;
    STANDARD
        .decode(
            answer["CiphertextBlob"]
                .as_str()
                .context("no CiphertextBlob")?,
        )
        .context("malformed CiphertextBlob")
}

async fn aws_decrypt(aws: &AwsKms, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = json!({"CiphertextBlob": STANDARD.encode(wrapped)});
    if let Some(key_id) = &aws.key_id {
        body["KeyId"] = json!(key_id);
    }
    let answer = aws_call(aws, "Decrypt", body).await?;
    Ok(Zeroizing::new(
        STANDARD
            .decode(answer["Plaintext"].as_str().context("no Plaintext")?)
            .context("malformed Plaintext")?,
    ))
}

// ---------------------------------------------------------------------------
// Google Cloud KMS
// ---------------------------------------------------------------------------

async fn gcp_token(gcp: &GcpKms) -> Result<Zeroizing<String>> {
    let client = http()?;
    if let Some(path) = &gcp.credentials_file {
        let account: Value = serde_json::from_str(&read_text_file(path, 64 * 1024)?)
            .context("the service account key file is not JSON")?;
        let token_uri = account["token_uri"]
            .as_str()
            .unwrap_or("https://oauth2.googleapis.com/token")
            .to_owned();
        let now = Utc::now().timestamp();
        let assertion = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &json!({
                "iss": account["client_email"],
                "scope": "https://www.googleapis.com/auth/cloudkms",
                "aud": token_uri,
                "iat": now,
                "exp": now + 600,
            }),
            &jsonwebtoken::EncodingKey::from_rsa_pem(
                account["private_key"]
                    .as_str()
                    .context("no private_key")?
                    .as_bytes(),
            )
            .context("the service account private key is not an RSA PEM key")?,
        )
        .context("sign the service account assertion")?;
        let answer: Value = client
            .post(token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?
            .error_for_status()
            .context("Google refused the service account")?
            .json()
            .await?;
        return Ok(Zeroizing::new(
            answer["access_token"]
                .as_str()
                .context("no access_token")?
                .to_owned(),
        ));
    }
    let host = gcp
        .metadata_host
        .as_deref()
        .unwrap_or("metadata.google.internal");
    let answer: Value = client
        .get(format!(
            "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
        ))
        .header("metadata-flavor", "Google")
        .send()
        .await
        .context("no GOOGLE_APPLICATION_CREDENTIALS and no metadata server")?
        .error_for_status()?
        .json()
        .await?;
    Ok(Zeroizing::new(
        answer["access_token"]
            .as_str()
            .context("no access_token")?
            .to_owned(),
    ))
}

/// `encrypt` or `decrypt` with a Cloud KMS key.
async fn gcp_crypt(gcp: &GcpKms, operation: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let token = gcp_token(gcp).await?;
    let endpoint = gcp
        .endpoint
        .as_deref()
        .unwrap_or("https://cloudkms.googleapis.com")
        .trim_end_matches('/');
    let (field, answer_field) = if operation == "encrypt" {
        ("plaintext", "ciphertext")
    } else {
        ("ciphertext", "plaintext")
    };
    let response = http()?
        .post(format!("{endpoint}/v1/{}:{operation}", gcp.key))
        .bearer_auth(token.as_str())
        .json(&json!({field: STANDARD.encode(data)}))
        .send()
        .await
        .context("reach Cloud KMS")?;
    let status = response.status();
    let answer: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!(
            "Cloud KMS {operation} failed ({status}): {}",
            answer["error"]["message"].as_str().unwrap_or("error")
        );
    }
    Ok(Zeroizing::new(
        STANDARD
            .decode(
                answer[answer_field]
                    .as_str()
                    .with_context(|| format!("no {answer_field}"))?,
            )
            .with_context(|| format!("malformed {answer_field}"))?,
    ))
}

// ---------------------------------------------------------------------------
// PKCS#11
// ---------------------------------------------------------------------------

#[cfg(not(feature = "pkcs11"))]
fn pkcs11_crypt(_: &Pkcs11Kms, _: bool, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    bail!("this keylease-server was built without PKCS#11 support (cargo feature pkcs11)")
}

/// AES-GCM with the token's key: `iv (12 bytes) || ciphertext || tag`.
#[cfg(feature = "pkcs11")]
fn pkcs11_crypt(settings: &Pkcs11Kms, encrypt: bool, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::{Mechanism, aead::GcmParams};
    use cryptoki::object::{Attribute, KeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use rand::RngCore;

    let pkcs11 = Pkcs11::new(&settings.module)
        .with_context(|| format!("load the PKCS#11 module {}", settings.module.display()))?;
    // The library stays initialized for the life of the process (the same
    // module may be loaded again, e.g. by `kms init`, which wraps then
    // unwraps).
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
        Err(error) => return Err(error).context("initialize the PKCS#11 module"),
    }
    let slot = pkcs11
        .get_slots_with_token()?
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .is_ok_and(|info| info.label().trim() == settings.token_label)
        })
        .with_context(|| format!("no PKCS#11 token labelled {}", settings.token_label))?;
    let session = pkcs11.open_ro_session(slot)?;
    session
        .login(
            UserType::User,
            Some(&AuthPin::from(settings.pin.as_str().to_owned())),
        )
        .context("log in to the PKCS#11 token")?;
    let key = *session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Label(settings.key_label.as_bytes().to_vec()),
        ])?
        .first()
        .with_context(|| format!("no AES key labelled {} on the token", settings.key_label))?;
    let result = if encrypt {
        let mut iv = [0_u8; 12];
        rand::rng().fill_bytes(&mut iv);
        let mut nonce = iv;
        let sealed = session.encrypt(
            &Mechanism::AesGcm(GcmParams::new(&mut nonce, PKCS11_AAD, 128.into())?),
            key,
            data,
        )?;
        let mut out = iv.to_vec();
        out.extend_from_slice(&sealed);
        Zeroizing::new(out)
    } else {
        if data.len() < 12 + 16 {
            bail!("the wrapped root key is too short");
        }
        let mut iv: [u8; 12] = data[..12].try_into()?;
        Zeroizing::new(session.decrypt(
            &Mechanism::AesGcm(GcmParams::new(&mut iv, PKCS11_AAD, 128.into())?),
            key,
            &data[12..],
        )?)
    };
    let _ = session.logout();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signing example from AWS's Signature Version 4 documentation
    /// (IAM `ListUsers`).
    #[test]
    fn sigv4_matches_the_aws_example() {
        let credentials = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
            session_token: None,
        };
        let authorization = sigv4_authorization(
            "GET",
            "/",
            "Action=ListUsers&Version=2010-05-08",
            &[
                (
                    "content-type",
                    "application/x-www-form-urlencoded; charset=utf-8",
                ),
                ("host", "iam.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            b"",
            &credentials,
            "us-east-1",
            "iam",
            "20150830T123600Z",
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn fingerprints_differ_per_key() {
        assert_ne!(fingerprint(&[1; 32]), fingerprint(&[2; 32]));
        assert_eq!(fingerprint(&[1; 32]).len(), 16);
    }
}
