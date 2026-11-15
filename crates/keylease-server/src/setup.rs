//! `keylease-server setup`: one command from a binary to a running server.
//!
//! It keeps everything in one directory (default
//! `~/.local/share/keylease-server`): generated secrets, `server.env`, and,
//! unless `--database-url-file` is given, a private PostgreSQL cluster that
//! listens only on a Unix socket inside that directory. On Linux with systemd
//! it installs and starts a service; elsewhere it prints the command to run.
//! Running it again keeps the secrets and the database and rewrites the rest.
//!
//! The server reads the same directory at start ([`load_env_file`]), so a
//! bare `keylease-server` runs what setup prepared, and [`ensure_postgres`]
//! starts the private cluster first when `server.env` names one.

use anyhow::{Context, Result, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use rand::RngCore;
use std::{
    env, fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const ENV_FILE: &str = "server.env";
const SERVICE: &str = "keylease-server.service";
const DATABASE: &str = "keylease";
const DB_ROLE: &str = "keylease";

struct Options {
    dir: PathBuf,
    listen: SocketAddr,
    public_url: Option<String>,
    database_url_file: Option<PathBuf>,
    service: bool,
}

fn usage() -> &'static str {
    "usage: keylease-server setup [--dir DIR] [--listen ADDR:PORT] [--public-url URL]\n\
     \x20                            [--database-url-file FILE] [--no-service]\n\
     \n\
     Generates the secrets, prepares PostgreSQL (a private cluster in DIR unless\n\
     --database-url-file is given), writes DIR/server.env and starts the server\n\
     as a systemd service. Safe to run again: secrets and data are kept."
}

/// The directory setup uses when none is given.
pub fn default_dir() -> PathBuf {
    if is_root() {
        return PathBuf::from("/var/lib/keylease-server");
    }
    let data = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    data.join("keylease-server")
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

fn parse(args: Vec<String>) -> Result<Options> {
    let mut options = Options {
        dir: default_dir(),
        listen: "127.0.0.1:8080".parse()?,
        public_url: None,
        database_url_file: None,
        service: true,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .with_context(|| format!("{name} needs a value\n\n{}", usage()))
        };
        match arg.as_str() {
            "--dir" => options.dir = PathBuf::from(value("--dir")?),
            "--listen" => {
                options.listen = value("--listen")?
                    .parse()
                    .context("--listen must be ADDRESS:PORT, e.g. 127.0.0.1:8080")?
            }
            "--public-url" => options.public_url = Some(value("--public-url")?),
            "--database-url-file" => {
                options.database_url_file = Some(PathBuf::from(value("--database-url-file")?))
            }
            "--no-service" => options.service = false,
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => bail!("unknown option {other}\n\n{}", usage()),
        }
    }
    if !options.dir.is_absolute() {
        options.dir = env::current_dir()?.join(&options.dir);
    }
    // The path goes into postgresql.conf, a connection URL and a unit file.
    let text = options.dir.to_string_lossy();
    if text
        .chars()
        .any(|c| c.is_whitespace() || "'\"\\%#?&".contains(c))
    {
        bail!("--dir must not contain spaces, quotes or any of \\ % # ? &: {text}");
    }
    Ok(options)
}

pub async fn run(args: Vec<String>) -> Result<()> {
    let options = parse(args)?;
    let dir = &options.dir;
    create_private_dir(dir)?;
    let secrets = dir.join("secrets");
    create_private_dir(&secrets)?;

    let admin_token = secrets.join("admin_token");
    write_new_secret(&admin_token, || {
        format!("kladmin_{}\n", URL_SAFE_NO_PAD.encode(random::<36>()))
    })?;
    write_new_secret(&secrets.join("control_signing_key"), || {
        format!("{}\n", STANDARD_NO_PAD.encode(random::<32>()))
    })?;
    let kms_created = write_new_secret(&secrets.join("kms_root_key"), || {
        format!("{}\n", STANDARD_NO_PAD.encode(random::<32>()))
    })?;

    let (database_url_file, postgres) = match &options.database_url_file {
        Some(file) => {
            let file =
                fs::canonicalize(file).with_context(|| format!("read {}", file.display()))?;
            (file, None)
        }
        None => {
            let cluster = prepare_postgres(dir).await?;
            let url_file = secrets.join("database_url");
            let url = format!(
                "postgres://{DB_ROLE}@localhost/{DATABASE}?host={}",
                cluster.data.display()
            );
            write_secret(&url_file, &format!("{url}\n"))?;
            (url_file, Some(cluster))
        }
    };

    let public_url = options
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://localhost:{}", options.listen.port()));
    let mut env_text = format!(
        "# Written by `keylease-server setup`; it rewrites this file when run again.\n\
         KEYLEASE_SERVER_LISTEN={listen}\n\
         KEYLEASE_SERVER_PUBLIC_URL={public_url}\n\
         KEYLEASE_DATABASE_URL_FILE={db}\n\
         KEYLEASE_ADMIN_TOKEN_FILE={admin}\n\
         KEYLEASE_CONTROL_SIGNING_KEY_FILE={sign}\n\
         KEYLEASE_KMS_ROOT_KEY_FILE={kms}\n",
        listen = options.listen,
        db = database_url_file.display(),
        admin = admin_token.display(),
        sign = secrets.join("control_signing_key").display(),
        kms = secrets.join("kms_root_key").display(),
    );
    if let Some(cluster) = &postgres {
        env_text.push_str(&format!(
            "KEYLEASE_EMBEDDED_POSTGRES={}\nKEYLEASE_PG_CTL={}\n",
            cluster.data.display(),
            cluster.pg_ctl.display()
        ));
    }
    write_secret(&dir.join(ENV_FILE), &env_text)?;

    let binary = env::current_exe().context("locate keylease-server")?;
    let started = if options.service && has_systemd() {
        // Hand the cluster to the service, which starts it in its own cgroup.
        if let Some(cluster) = &postgres {
            stop_cluster(cluster)?;
        }
        install_service(&binary, dir)?;
        wait_ready(options.listen).await
    } else {
        false
    };

    println!();
    println!("KeyLease server is set up in {}", dir.display());
    if started {
        println!("  Running:     {SERVICE} ({})", service_scope_hint());
    } else if options.service && !has_systemd() {
        println!("  No systemd here. Start it with:  {}", binary.display());
    } else if options.service {
        println!(
            "  The service did not answer yet. Check: journalctl {}-u keylease-server -e",
            if is_root() { "" } else { "--user " }
        );
    } else {
        println!("  Start it with:  {}", binary.display());
    }
    println!("  Console:     {public_url}/console/");
    println!("  API:         {public_url}");
    println!("  Admin token: {}", admin_token.display());
    if postgres.is_some() {
        println!(
            "  Database:    private PostgreSQL in {}/pg (Unix socket only)",
            dir.display()
        );
    }
    if kms_created {
        println!();
        println!(
            "Back up {} somewhere else (it encrypts Managed secrets; without it they are lost).",
            secrets.join("kms_root_key").display()
        );
    }
    if options.listen.ip().is_loopback() && !public_url.contains("localhost") {
        println!();
        println!(
            "It listens on {} only: put a reverse proxy for {public_url} in front of it.",
            options.listen
        );
    } else if options.listen.ip().is_loopback() {
        println!();
        println!(
            "It listens on this machine only. From another computer:  ssh -N -L {port}:127.0.0.1:{port} THIS_HOST",
            port = options.listen.port()
        );
    }
    println!();
    println!("Next, link a vault as its owner:");
    println!(
        "  keylease cloud init --url {public_url} --admin-token-file {} && keylease cloud console",
        admin_token.display()
    );
    Ok(())
}

// ---- files -------------------------------------------------------------------

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {}", dir.display()))?;
    }
    Ok(())
}

/// Writes `path` (mode 0600) only when it does not exist. Returns whether it
/// was written.
fn write_new_secret(path: &Path, make: impl FnOnce() -> String) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    write_secret(path, &make())?;
    Ok(true)
}

fn write_secret(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Reads `KEY=VALUE` lines of `DIR/server.env` into the environment, without
/// replacing what is already set. `DIR` is `KEYLEASE_SERVER_DIR` or the
/// default. Called before the server reads its configuration, so a bare
/// `keylease-server` runs what setup prepared. Returns the file it read.
pub fn load_env_file() -> Result<Option<PathBuf>> {
    let dir = env::var_os("KEYLEASE_SERVER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_dir);
    let path = dir.join(ENV_FILE);
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(None);
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("{}: not KEY=VALUE: {line}", path.display());
        };
        if !key.starts_with("KEYLEASE_") {
            bail!(
                "{}: only KEYLEASE_* settings belong here: {key}",
                path.display()
            );
        }
        if env::var_os(key).is_none() {
            // SAFETY: called once at start-up, before any other thread exists.
            unsafe { env::set_var(key, value) };
        }
    }
    Ok(Some(path))
}

// ---- PostgreSQL --------------------------------------------------------------

struct Cluster {
    data: PathBuf,
    pg_ctl: PathBuf,
}

/// Finds `initdb` and `pg_ctl`: on PATH, else the newest of the usual
/// package locations.
fn find_postgres_bin() -> Option<PathBuf> {
    let has = |dir: &Path| dir.join("initdb").is_file() && dir.join("pg_ctl").is_file();
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            if has(&dir) {
                return Some(dir);
            }
        }
    }
    let mut candidates: Vec<(u32, PathBuf)> = Vec::new();
    for (root, prefix, suffix) in [
        ("/usr/lib/postgresql", "", "bin"),
        ("/usr", "pgsql-", "bin"),
        ("/opt/homebrew/opt", "postgresql@", "bin"),
        ("/usr/local/opt", "postgresql@", "bin"),
    ] {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(version) = name
                .strip_prefix(prefix)
                .and_then(|v| v.parse::<u32>().ok())
            else {
                continue;
            };
            let dir = entry.path().join(suffix);
            if has(&dir) {
                candidates.push((version, dir));
            }
        }
    }
    candidates.sort();
    candidates.pop().map(|(_, dir)| dir)
}

async fn prepare_postgres(dir: &Path) -> Result<Cluster> {
    if is_root() {
        bail!(
            "PostgreSQL refuses to run as root. Run setup as the user the server should run as, \
             or pass --database-url-file with a URL to an existing database."
        );
    }
    let bin = find_postgres_bin().context(
        "PostgreSQL is not installed (no initdb/pg_ctl found). Install it \
         (Debian/Ubuntu: apt install postgresql; macOS: brew install postgresql@17), \
         or pass --database-url-file with a URL to an existing database.",
    )?;
    let data = dir.join("pg");
    let cluster = Cluster {
        data: data.clone(),
        pg_ctl: bin.join("pg_ctl"),
    };
    if !data.join("PG_VERSION").is_file() {
        println!(
            "Creating a private PostgreSQL cluster in {}",
            data.display()
        );
        let status = Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(&data)
            .args([
                "-U",
                DB_ROLE,
                "--auth=trust",
                "--encoding=UTF8",
                "--no-instructions",
            ])
            .stdout(std::process::Stdio::null())
            .status()
            .context("run initdb")?;
        if !status.success() {
            bail!("initdb failed");
        }
        // Trust is safe because nothing but this user can reach the socket:
        // no TCP listener, and the socket lives in a mode-0700 directory.
        let mut conf = fs::OpenOptions::new()
            .append(true)
            .open(data.join("postgresql.conf"))?;
        writeln!(
            conf,
            "\n# keylease-server setup: Unix socket in this directory only.\n\
             listen_addresses = ''\nunix_socket_directories = '{}'",
            data.display()
        )?;
    }
    start_cluster(&cluster)?;
    create_database(&data).await?;
    Ok(cluster)
}

fn cluster_running(cluster: &Cluster) -> bool {
    Command::new(&cluster.pg_ctl)
        .arg("-D")
        .arg(&cluster.data)
        .arg("status")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn start_cluster(cluster: &Cluster) -> Result<()> {
    if cluster_running(cluster) {
        return Ok(());
    }
    let status = Command::new(&cluster.pg_ctl)
        .arg("-D")
        .arg(&cluster.data)
        .arg("-l")
        .arg(cluster.data.join("postgres.log"))
        .args(["-w", "-t", "60", "start"])
        .stdout(std::process::Stdio::null())
        .status()
        .context("run pg_ctl start")?;
    if !status.success() {
        bail!(
            "PostgreSQL did not start; see {}",
            cluster.data.join("postgres.log").display()
        );
    }
    Ok(())
}

fn stop_cluster(cluster: &Cluster) -> Result<()> {
    if !cluster_running(cluster) {
        return Ok(());
    }
    let status = Command::new(&cluster.pg_ctl)
        .arg("-D")
        .arg(&cluster.data)
        .args(["-m", "fast", "-w", "stop"])
        .stdout(std::process::Stdio::null())
        .status()
        .context("run pg_ctl stop")?;
    if !status.success() {
        bail!("PostgreSQL did not stop");
    }
    Ok(())
}

async fn create_database(data: &Path) -> Result<()> {
    use sqlx::{Connection, Row, postgres::PgConnection};
    let url = format!(
        "postgres://{DB_ROLE}@localhost/postgres?host={}",
        data.display()
    );
    let mut connection = PgConnection::connect(&url)
        .await
        .context("connect to the private PostgreSQL")?;
    let exists = sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(DATABASE)
        .fetch_optional(&mut connection)
        .await?
        .map(|row| row.get::<i32, _>(0) == 1)
        .unwrap_or(false);
    if !exists {
        sqlx::query("CREATE DATABASE keylease")
            .execute(&mut connection)
            .await
            .context("create the keylease database")?;
    }
    Ok(())
}

/// Starts the private cluster `server.env` names, if any; the server calls it
/// before connecting.
pub fn ensure_postgres() -> Result<()> {
    let (Some(data), Some(pg_ctl)) = (
        env::var_os("KEYLEASE_EMBEDDED_POSTGRES"),
        env::var_os("KEYLEASE_PG_CTL"),
    ) else {
        return Ok(());
    };
    start_cluster(&Cluster {
        data: data.into(),
        pg_ctl: pg_ctl.into(),
    })
}

// ---- service -----------------------------------------------------------------

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
        && Command::new("systemctl")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
}

fn service_scope_hint() -> &'static str {
    if is_root() {
        "systemctl status keylease-server"
    } else {
        "systemctl --user status keylease-server"
    }
}

fn install_service(binary: &Path, dir: &Path) -> Result<()> {
    let root = is_root();
    let unit_dir = if root {
        PathBuf::from("/etc/systemd/system")
    } else {
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("HOME is not set")?;
        config.join("systemd/user")
    };
    fs::create_dir_all(&unit_dir)?;
    // Postgres is started by the server (pg_ctl) and lives in the service's
    // cgroup: stopping the service sends it SIGTERM too (a clean shutdown).
    let unit = format!(
        "[Unit]\n\
         Description=KeyLease server\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         EnvironmentFile={env}\n\
         ExecStart={binary}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         KillMode=mixed\n\
         TimeoutStopSec=30\n\
         \n\
         [Install]\n\
         WantedBy={target}\n",
        env = dir.join(ENV_FILE).display(),
        binary = binary.display(),
        target = if root {
            "multi-user.target"
        } else {
            "default.target"
        },
    );
    fs::write(unit_dir.join(SERVICE), unit)?;
    let systemctl = |args: &[&str]| -> Result<()> {
        let mut command = Command::new("systemctl");
        if !root {
            command.arg("--user");
        }
        let status = command.args(args).status().context("run systemctl")?;
        if !status.success() {
            bail!("systemctl {} failed", args.join(" "));
        }
        Ok(())
    };
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", SERVICE])?;
    systemctl(&["restart", SERVICE])?;
    if !root {
        let user = env::var("USER").unwrap_or_default();
        let linger = Command::new("loginctl")
            .args(["show-user", &user, "-p", "Linger"])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "Linger=yes")
            .unwrap_or(true);
        if !linger {
            println!(
                "Note: the service stops when you log out. Keep it running with:  sudo loginctl enable-linger {user}"
            );
        }
    }
    Ok(())
}

async fn wait_ready(listen: SocketAddr) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    let host = if listen.ip().is_unspecified() {
        "127.0.0.1".to_owned()
    } else {
        listen.ip().to_string()
    };
    let url = format!("http://{host}:{}/readyz", listen.port());
    for _ in 0..60 {
        if client
            .get(&url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_paths_that_break_the_config() {
        assert!(parse(vec!["--dir".into(), "/tmp/a b".into()]).is_err());
        assert!(parse(vec!["--dir".into(), "/tmp/a'b".into()]).is_err());
        let ok = parse(vec![
            "--dir".into(),
            "/tmp/kl".into(),
            "--listen".into(),
            "127.0.0.1:18080".into(),
            "--no-service".into(),
        ])
        .unwrap();
        assert_eq!(ok.listen.port(), 18080);
        assert!(!ok.service);
    }

    #[test]
    fn secrets_are_written_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        assert!(write_new_secret(&path, || "a\n".into()).unwrap());
        assert!(!write_new_secret(&path, || "b\n".into()).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "a\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
