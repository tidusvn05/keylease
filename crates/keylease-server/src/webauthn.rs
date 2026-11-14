//! The part of WebAuthn (passkeys) the console needs: ES256 credentials,
//! `none` attestation (the authenticator's maker is not checked), user
//! presence required, signature counters checked when the authenticator
//! keeps one.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    Malformed(&'static str),
    Mismatch(&'static str),
    BadSignature,
}

type Result<T> = std::result::Result<T, WebAuthnError>;

/// A minimal CBOR value: what attestation objects and COSE keys use.
#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Simple(u8),
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(WebAuthnError::Malformed("truncated CBOR"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn argument(&mut self, info: u8) -> Result<u64> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().unwrap_or_default(),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().unwrap_or_default(),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap_or_default()),
            _ => return Err(WebAuthnError::Malformed("unsupported CBOR length")),
        })
    }

    fn value(&mut self, depth: u8) -> Result<Cbor> {
        if depth > 8 {
            return Err(WebAuthnError::Malformed("CBOR nested too deeply"));
        }
        let head = self.take(1)?[0];
        let (major, info) = (head >> 5, head & 0x1f);
        let length = |reader: &mut Self| -> Result<usize> {
            let length = reader.argument(info)?;
            usize::try_from(length)
                .ok()
                .filter(|length| *length <= reader.bytes.len())
                .ok_or(WebAuthnError::Malformed("CBOR length out of range"))
        };
        Ok(match major {
            0 => Cbor::Unsigned(self.argument(info)?),
            1 => {
                let value = self.argument(info)?;
                Cbor::Negative(
                    -1 - i64::try_from(value)
                        .map_err(|_| WebAuthnError::Malformed("CBOR integer"))?,
                )
            }
            2 => {
                let length = length(self)?;
                Cbor::Bytes(self.take(length)?.to_vec())
            }
            3 => {
                let length = length(self)?;
                Cbor::Text(
                    String::from_utf8(self.take(length)?.to_vec())
                        .map_err(|_| WebAuthnError::Malformed("CBOR text"))?,
                )
            }
            4 => {
                let length = length(self)?;
                let mut items = Vec::with_capacity(length.min(64));
                for _ in 0..length {
                    items.push(self.value(depth + 1)?);
                }
                Cbor::Array(items)
            }
            5 => {
                let length = length(self)?;
                let mut entries = Vec::with_capacity(length.min(64));
                for _ in 0..length {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Cbor::Map(entries)
            }
            7 if info < 24 => Cbor::Simple(info),
            _ => return Err(WebAuthnError::Malformed("unsupported CBOR item")),
        })
    }
}

/// Decodes one CBOR item; returns it and how many bytes it used.
fn decode(bytes: &[u8]) -> Result<(Cbor, usize)> {
    let mut reader = Reader { bytes, position: 0 };
    let value = reader.value(0)?;
    Ok((value, reader.position))
}

fn map_get<'a>(map: &'a [(Cbor, Cbor)], key: &Cbor) -> Option<&'a Cbor> {
    map.iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

/// A COSE EC2 P-256 key (`kty` 2, `alg` -7, `crv` 1) as an SEC1 point.
fn cose_es256_key(cose: &Cbor) -> Result<Vec<u8>> {
    let Cbor::Map(map) = cose else {
        return Err(WebAuthnError::Malformed("COSE key is not a map"));
    };
    let int = |key: i64| -> Cbor {
        if key < 0 {
            Cbor::Negative(key)
        } else {
            Cbor::Unsigned(key as u64)
        }
    };
    if map_get(map, &int(1)) != Some(&Cbor::Unsigned(2))
        || map_get(map, &int(3)) != Some(&Cbor::Negative(-7))
        || map_get(map, &int(-1)) != Some(&Cbor::Unsigned(1))
    {
        return Err(WebAuthnError::Mismatch(
            "only ES256 (P-256) passkeys are supported",
        ));
    }
    let (Some(Cbor::Bytes(x)), Some(Cbor::Bytes(y))) =
        (map_get(map, &int(-2)), map_get(map, &int(-3)))
    else {
        return Err(WebAuthnError::Malformed("COSE key coordinates"));
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(WebAuthnError::Malformed("COSE key coordinates"));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| WebAuthnError::Malformed("not a P-256 point"))?;
    Ok(point)
}

/// Checks `clientDataJSON` and returns its SHA-256.
pub fn verify_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    challenge: &[u8],
    origin: &str,
) -> Result<[u8; 32]> {
    let data: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|_| WebAuthnError::Malformed("clientDataJSON"))?;
    if data["type"] != expected_type {
        return Err(WebAuthnError::Mismatch("ceremony type"));
    }
    let received = data["challenge"]
        .as_str()
        .and_then(|value| URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok())
        .ok_or(WebAuthnError::Malformed("challenge"))?;
    if received != challenge {
        return Err(WebAuthnError::Mismatch("challenge"));
    }
    if data["origin"] != origin {
        return Err(WebAuthnError::Mismatch("origin"));
    }
    if data["crossOrigin"].as_bool() == Some(true) {
        return Err(WebAuthnError::Mismatch("cross-origin ceremony"));
    }
    Ok(Sha256::digest(client_data_json).into())
}

pub struct AuthenticatorData {
    pub sign_count: u32,
    /// `(credential id, SEC1 public key)` from a registration.
    pub credential: Option<(Vec<u8>, Vec<u8>)>,
}

fn parse_authenticator_data(data: &[u8], rp_id: &str) -> Result<AuthenticatorData> {
    if data.len() < 37 {
        return Err(WebAuthnError::Malformed("authenticator data too short"));
    }
    if data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(WebAuthnError::Mismatch("relying party"));
    }
    let flags = data[32];
    if flags & 0x01 == 0 {
        return Err(WebAuthnError::Mismatch("user presence"));
    }
    let sign_count = u32::from_be_bytes(data[33..37].try_into().unwrap_or_default());
    let credential = if flags & 0x40 != 0 {
        let rest = &data[37..];
        if rest.len() < 18 {
            return Err(WebAuthnError::Malformed("attested credential data"));
        }
        let length = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        let id = rest
            .get(18..18 + length)
            .ok_or(WebAuthnError::Malformed("credential id"))?
            .to_vec();
        let (cose, _) = decode(&rest[18 + length..])?;
        Some((id, cose_es256_key(&cose)?))
    } else {
        None
    };
    Ok(AuthenticatorData {
        sign_count,
        credential,
    })
}

/// A new passkey from `navigator.credentials.create()`.
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: &[u8],
    origin: &str,
    rp_id: &str,
) -> Result<Registration> {
    verify_client_data(client_data_json, "webauthn.create", challenge, origin)?;
    let (object, _) = decode(attestation_object)?;
    let Cbor::Map(map) = object else {
        return Err(WebAuthnError::Malformed("attestation object"));
    };
    let Some(Cbor::Bytes(auth_data)) = map_get(&map, &Cbor::Text("authData".into())) else {
        return Err(WebAuthnError::Malformed("authData"));
    };
    let data = parse_authenticator_data(auth_data, rp_id)?;
    let (credential_id, public_key) = data
        .credential
        .ok_or(WebAuthnError::Malformed("no credential in registration"))?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(WebAuthnError::Malformed("credential id"));
    }
    Ok(Registration {
        credential_id,
        public_key,
        sign_count: data.sign_count,
    })
}

/// Checks a sign-in assertion; returns the new signature counter.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
    stored_count: u32,
    challenge: &[u8],
    origin: &str,
    rp_id: &str,
) -> Result<u32> {
    let client_hash = verify_client_data(client_data_json, "webauthn.get", challenge, origin)?;
    let data = parse_authenticator_data(authenticator_data, rp_id)?;
    let key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| WebAuthnError::Malformed("stored key"))?;
    let signature =
        Signature::from_der(signature_der).map_err(|_| WebAuthnError::Malformed("signature"))?;
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&client_hash);
    key.verify(&signed, &signature)
        .map_err(|_| WebAuthnError::BadSignature)?;
    // A counter that does not increase means a cloned authenticator; zero
    // means the authenticator keeps no counter (common for synced passkeys).
    if (data.sign_count != 0 || stored_count != 0) && data.sign_count <= stored_count {
        return Err(WebAuthnError::Mismatch(
            "signature counter did not increase",
        ));
    }
    Ok(data.sign_count)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    pub(crate) const RP_ID: &str = "vault.example.com";
    pub(crate) const ORIGIN: &str = "https://vault.example.com";

    fn cbor_bytes(out: &mut Vec<u8>, major: u8, bytes: &[u8]) {
        head(out, major, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn head(out: &mut Vec<u8>, major: u8, value: u64) {
        if value < 24 {
            out.push((major << 5) | value as u8);
        } else if value < 256 {
            out.push((major << 5) | 24);
            out.push(value as u8);
        } else {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
    }

    pub(crate) fn cose_key(key: &SigningKey) -> Vec<u8> {
        let point = key.verifying_key().to_encoded_point(false);
        let mut out = vec![0xa5]; // map(5)
        out.extend_from_slice(&[0x01, 0x02]); // kty: EC2
        out.extend_from_slice(&[0x03, 0x26]); // alg: -7
        out.extend_from_slice(&[0x20, 0x01]); // crv(-1): P-256
        out.push(0x21); // x(-2)
        cbor_bytes(&mut out, 2, point.x().unwrap());
        out.push(0x22); // y(-3)
        cbor_bytes(&mut out, 2, point.y().unwrap());
        out
    }

    pub(crate) fn authenticator_data(
        count: u32,
        credential: Option<(&[u8], &SigningKey)>,
    ) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        data.push(if credential.is_some() { 0x45 } else { 0x05 });
        data.extend_from_slice(&count.to_be_bytes());
        if let Some((id, key)) = credential {
            data.extend_from_slice(&[0_u8; 16]);
            data.extend_from_slice(&(id.len() as u16).to_be_bytes());
            data.extend_from_slice(id);
            data.extend_from_slice(&cose_key(key));
        }
        data
    }

    pub(crate) fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": ORIGIN,
        }))
        .unwrap()
    }

    pub(crate) fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let mut out = vec![0xa3];
        cbor_bytes(&mut out, 3, b"fmt");
        cbor_bytes(&mut out, 3, b"none");
        cbor_bytes(&mut out, 3, b"attStmt");
        out.push(0xa0);
        cbor_bytes(&mut out, 3, b"authData");
        cbor_bytes(&mut out, 2, auth_data);
        out
    }

    pub(crate) fn sign(key: &SigningKey, auth_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data_json));
        let signature: Signature = key.sign(&message);
        signature.to_der().as_bytes().to_vec()
    }

    #[test]
    fn a_passkey_registers_and_signs_in() {
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge = [7_u8; 32];
        let registration = verify_registration(
            &client_data("webauthn.create", &challenge),
            &attestation_object(&authenticator_data(0, Some((b"cred-1", &key)))),
            &challenge,
            ORIGIN,
            RP_ID,
        )
        .unwrap();
        assert_eq!(registration.credential_id, b"cred-1");
        let login = [9_u8; 32];
        let auth = authenticator_data(5, None);
        let data = client_data("webauthn.get", &login);
        let signature = sign(&key, &auth, &data);
        assert_eq!(
            verify_assertion(
                &data,
                &auth,
                &signature,
                &registration.public_key,
                0,
                &login,
                ORIGIN,
                RP_ID
            ),
            Ok(5)
        );
        // Replays and a lower counter fail; so do another challenge, origin or key.
        assert!(
            verify_assertion(
                &data,
                &auth,
                &signature,
                &registration.public_key,
                5,
                &login,
                ORIGIN,
                RP_ID
            )
            .is_err()
        );
        assert!(
            verify_assertion(
                &data,
                &auth,
                &signature,
                &registration.public_key,
                0,
                &[1; 32],
                ORIGIN,
                RP_ID
            )
            .is_err()
        );
        assert!(
            verify_assertion(
                &data,
                &auth,
                &signature,
                &registration.public_key,
                0,
                &login,
                "https://evil.example",
                RP_ID
            )
            .is_err()
        );
        assert!(
            verify_assertion(
                &data,
                &auth,
                &signature,
                &registration.public_key,
                0,
                &login,
                ORIGIN,
                "evil.example"
            )
            .is_err()
        );
        let other = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let forged = sign(&other, &auth, &data);
        assert_eq!(
            verify_assertion(
                &data,
                &auth,
                &forged,
                &registration.public_key,
                0,
                &login,
                ORIGIN,
                RP_ID
            ),
            Err(WebAuthnError::BadSignature)
        );
        // A registration ceremony's client data does not sign in.
        let wrong_type = client_data("webauthn.create", &login);
        let signature = sign(&key, &auth, &wrong_type);
        assert!(
            verify_assertion(
                &wrong_type,
                &auth,
                &signature,
                &registration.public_key,
                0,
                &login,
                ORIGIN,
                RP_ID
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_cbor_is_rejected_without_panicking() {
        for bytes in [
            &[][..],
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xbf],
            &[0x9f],
        ] {
            assert!(decode(bytes).is_err());
        }
        assert!(verify_registration(b"{}", &[0xa0], &[0; 32], ORIGIN, RP_ID).is_err());
    }
}
