//! `keylease-server setup --domain NAME` and `--tunnel tailscale`: put the
//! server on a real HTTPS address without hand-writing proxy config.
//!
//! The server keeps listening on loopback; something that already handles
//! TLS well sits in front of it:
//!
//! - **Caddy** (preferred: it gets and renews the certificate itself). Setup
//!   writes a site file and the two or three commands that enable it, and
//!   runs them with sudo when you say so.
//! - **nginx**, when it is what the machine runs: a server block plus
//!   certbot for the certificate.
//! - **Tailscale** (`--tunnel tailscale`), for a machine with no public
//!   address, such as a Mac at home: `tailscale serve` gives it
//!   `https://NAME.TAILNET.ts.net` with a real certificate, reachable from
//!   your devices on the tailnet only.
//!
//! Nothing here edits system files by itself: every command is printed
//! first, and run only after a yes at a terminal.

use anyhow::{Context, Result, bail};
use std::{
    fs,
    io::{BufRead, IsTerminal, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// A host name a certificate can be issued for.
pub fn valid_domain(name: &str) -> Result<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = name
        .strip_prefix("https://")
        .or_else(|| name.strip_prefix("http://"))
        .unwrap_or(&name)
        .trim_end_matches('/')
        .to_string();
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if name.len() > 253 || !name.contains('.') || !name.split('.').all(label_ok) {
        bail!("--domain must be a host name such as keys.example.com, not {name:?}");
    }
    Ok(name)
}

// ---- DNS ---------------------------------------------------------------------

/// Cloudflare's published proxy ranges (cloudflare.com/ips).
const CLOUDFLARE: &[(&str, u8)] = &[
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("131.0.72.0", 22),
    ("2400:cb00::", 32),
    ("2606:4700::", 32),
    ("2803:f800::", 32),
    ("2405:b500::", 32),
    ("2405:8100::", 32),
    ("2a06:98c0::", 29),
    ("2c0f:f248::", 32),
];

fn in_range(ip: IpAddr, base: &str, bits: u8) -> bool {
    match (ip, base.parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(base))) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(ip), Ok(IpAddr::V6(base))) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}

fn is_cloudflare(ip: IpAddr) -> bool {
    CLOUDFLARE
        .iter()
        .any(|(base, bits)| in_range(ip, base, *bits))
}

/// Whether `ip` is an address of this machine: binding to it only works
/// then.
fn is_local(ip: IpAddr) -> bool {
    UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Where the name points, as setup reports it.
#[derive(Debug, PartialEq, Eq)]
pub enum Dns {
    /// To an address of this machine.
    Here,
    /// Through Cloudflare's proxy.
    Cloudflare,
    /// Somewhere else (or behind NAT): it may still be right.
    Elsewhere(Vec<IpAddr>),
    /// Not at all yet.
    Missing,
}

pub fn check_dns(domain: &str) -> Dns {
    let addresses: Vec<IpAddr> = match (domain, 443).to_socket_addrs() {
        Ok(found) => found.map(|address| address.ip()).collect(),
        Err(_) => return Dns::Missing,
    };
    classify(&addresses, is_local)
}

fn classify(addresses: &[IpAddr], local: impl Fn(IpAddr) -> bool) -> Dns {
    if addresses.is_empty() {
        Dns::Missing
    } else if addresses.iter().any(|ip| local(*ip)) {
        Dns::Here
    } else if addresses.iter().all(|ip| is_cloudflare(*ip)) {
        Dns::Cloudflare
    } else {
        Dns::Elsewhere(addresses.to_vec())
    }
}

// ---- reverse proxies -----------------------------------------------------------

fn have(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .is_ok_and(|out| out.status.success())
}

/// What will serve HTTPS for the domain, and how to enable it.
pub struct ProxyPlan {
    pub kind: &'static str,
    /// The site file setup wrote, in the server's directory.
    pub file: PathBuf,
    /// Shell lines that enable it (some use sudo).
    pub commands: Vec<String>,
    /// Things to know before running them.
    pub notes: Vec<String>,
    /// Why running them now would not work.
    pub blockers: Vec<String>,
}

/// TLS files for Caddy when automatic HTTPS is off on this machine (an
/// origin certificate from Cloudflare, say).
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn brew_prefix() -> Option<PathBuf> {
    let out = Command::new("brew").arg("--prefix").output().ok()?;
    out.status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

/// The Caddyfile in use: Linux packages, or Homebrew on macOS.
pub fn caddyfile() -> Option<PathBuf> {
    let system = PathBuf::from("/etc/caddy/Caddyfile");
    if system.is_file() {
        return Some(system);
    }
    brew_prefix()
        .map(|prefix| prefix.join("etc/Caddyfile"))
        .filter(|path| path.is_file() || have("caddy"))
}

pub fn has_nginx() -> bool {
    Path::new("/etc/nginx").is_dir() && have("nginx")
}

/// Whether the Caddyfile turns automatic HTTPS off (certificates are then
/// given by hand, e.g. Cloudflare origin certificates).
pub fn auto_https_off(caddyfile: &Path) -> bool {
    fs::read_to_string(caddyfile)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .any(|line| {
            !line.starts_with('#') && line.starts_with("auto_https") && line.contains("off")
        })
}

/// Certificate pairs other sites in the Caddyfile use (`tls CERT KEY`).
pub fn tls_examples(caddyfile: &Path) -> Vec<TlsFiles> {
    let mut found: Vec<TlsFiles> = Vec::new();
    for line in fs::read_to_string(caddyfile).unwrap_or_default().lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let ["tls", cert, key] = words.as_slice()
            && !found.iter().any(|t| t.cert == Path::new(cert))
        {
            found.push(TlsFiles {
                cert: cert.into(),
                key: key.into(),
            });
        }
    }
    found
}

/// A command that installs Caddy here, when setup knows one.
pub fn caddy_install_command() -> Option<String> {
    let hint = caddy_install_hint();
    (!hint.starts_with("see ")).then_some(hint)
}

/// The address this machine uses to reach the internet (no packet is sent).
/// On a VPS it is usually the public address a DNS record should name.
pub fn outbound_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    let private = match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.octets()[0] == 100
        }
        IpAddr::V6(_) => true,
    };
    (!private).then_some(ip)
}

pub fn caddy_site(domain: &str, port: u16, tls: Option<&TlsFiles>) -> String {
    let tls = tls.map_or(String::new(), |tls| {
        format!("\ttls {} {}\n", tls.cert.display(), tls.key.display())
    });
    format!(
        "# KeyLease server, written by `keylease-server setup --domain {domain}`.\n\
         https://{domain} {{\n\
         {tls}\
         \treverse_proxy 127.0.0.1:{port}\n\
         }}\n"
    )
}

pub fn nginx_site(domain: &str, port: u16) -> String {
    format!(
        "# KeyLease server, written by `keylease-server setup --domain {domain}`.\n\
         # certbot --nginx adds the HTTPS part.\n\
         server {{\n\
         \x20   listen 80;\n\
         \x20   server_name {domain};\n\
         \x20   client_max_body_size 16m;\n\
         \x20   location / {{\n\
         \x20       proxy_pass http://127.0.0.1:{port};\n\
         \x20       proxy_http_version 1.1;\n\
         \x20       proxy_set_header Host $host;\n\
         \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
         \x20       proxy_set_header X-Forwarded-Proto $scheme;\n\
         \x20       proxy_set_header Upgrade $http_upgrade;\n\
         \x20       proxy_set_header Connection \"upgrade\";\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Writes the site file for the proxy this machine has and returns how to
/// enable it. Fails with install advice when there is none.
pub fn plan_proxy(
    dir: &Path,
    domain: &str,
    port: u16,
    tls: Option<&TlsFiles>,
    dns: &Dns,
) -> Result<ProxyPlan> {
    let proxy_dir = dir.join("proxy");
    fs::create_dir_all(&proxy_dir).with_context(|| format!("create {}", proxy_dir.display()))?;
    let mut notes = Vec::new();
    let mut blockers = Vec::new();
    if let Some(caddyfile) = caddyfile() {
        let file = proxy_dir.join("keylease.caddy");
        let current = fs::read_to_string(&caddyfile).unwrap_or_default();
        let auto_https_off = current.lines().any(|line| {
            let line = line.trim();
            !line.starts_with('#') && line.starts_with("auto_https") && line.contains("off")
        });
        fs::write(&file, caddy_site(domain, port, tls))?;
        let ours = |line: &str| line.contains("keylease");
        if current.lines().any(|line| {
            !ours(line)
                && line
                    .split_whitespace()
                    .any(|word| word.trim_start_matches("https://").trim_end_matches('{') == domain)
        }) {
            blockers.push(format!(
                "{} already has a site for {domain}; choose another name, or replace that site \
                 with the one above.",
                caddyfile.display()
            ));
        }
        if auto_https_off && tls.is_none() {
            let examples: Vec<&str> = current
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("tls ") && line.split_whitespace().count() == 3)
                .collect();
            blockers.push(format!(
                "{} turns automatic HTTPS off, so Caddy needs the certificate files for {domain}: \
                 run setup again with --tls-cert FILE --tls-key FILE{}",
                caddyfile.display(),
                examples.first().map_or(String::new(), |line| format!(
                    " (another site here uses `{line}`; reuse it if that certificate covers \
                     {domain})"
                ))
            ));
        } else if *dns == Dns::Cloudflare && tls.is_none() {
            notes.push(format!(
                "{domain} goes through Cloudflare's proxy. Either set Cloudflare's SSL mode to \
                 Full (strict) and pass a Cloudflare origin certificate with --tls-cert/--tls-key, \
                 or switch the record to DNS only while Caddy gets its certificate."
            ));
        }
        let config_dir = caddyfile.parent().unwrap_or(Path::new("/etc/caddy"));
        let target = config_dir.join(format!("keylease-{domain}.caddy"));
        let system = caddyfile.starts_with("/etc");
        let sudo = if system { "sudo " } else { "" };
        let mut commands = vec![format!(
            "{sudo}install -m 644 {} {}",
            file.display(),
            target.display()
        )];
        let import = format!("import {}", target.display());
        if !current.lines().any(|line| line.trim() == import) {
            commands.push(format!(
                "echo '{import}' | {sudo}tee -a {} >/dev/null",
                caddyfile.display()
            ));
        }
        commands.push(if system {
            "sudo systemctl reload caddy".into()
        } else {
            "brew services restart caddy".into()
        });
        return Ok(ProxyPlan {
            kind: "Caddy",
            file,
            commands,
            notes,
            blockers,
        });
    }
    if has_nginx() {
        let file = proxy_dir.join("keylease.conf");
        fs::write(&file, nginx_site(domain, port))?;
        let blockers = Vec::new();
        if *dns == Dns::Cloudflare {
            notes.push(format!(
                "{domain} goes through Cloudflare's proxy; certbot's HTTP check works when \
                 Cloudflare reaches this machine on port 80."
            ));
        }
        return Ok(ProxyPlan {
            kind: "nginx",
            commands: vec![
                format!(
                    "sudo install -m 644 {} /etc/nginx/conf.d/keylease.conf",
                    file.display()
                ),
                "sudo nginx -t".into(),
                "sudo systemctl reload nginx".into(),
                format!("sudo certbot --nginx -d {domain}"),
            ],
            file,
            notes,
            blockers,
        });
    }
    bail!(
        "nothing on this machine serves HTTPS yet. Install Caddy (it gets and renews the \
         certificate by itself), then run this again:\n  {}\n\
         Or, with no public address, use Tailscale instead:  --tunnel tailscale",
        caddy_install_hint()
    )
}

fn caddy_install_hint() -> String {
    if cfg!(target_os = "macos") {
        return "brew install caddy && brew services start caddy".into();
    }
    let release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let ids: String = release
        .lines()
        .filter(|line| line.starts_with("ID=") || line.starts_with("ID_LIKE="))
        .collect::<Vec<_>>()
        .join(" ");
    if ids.contains("debian") || ids.contains("ubuntu") {
        "sudo apt install caddy".into()
    } else if ids.contains("fedora") || ids.contains("rhel") || ids.contains("centos") {
        "sudo dnf install caddy && sudo systemctl enable --now caddy".into()
    } else if ids.contains("arch") {
        "sudo pacman -S caddy && sudo systemctl enable --now caddy".into()
    } else {
        "see https://caddyserver.com/docs/install".into()
    }
}

/// Shows the plan and, at a terminal, offers to run it. Returns whether it
/// ran (and succeeded).
pub fn offer(plan: &ProxyPlan) -> Result<bool> {
    println!();
    println!(
        "{} will serve HTTPS. Site file: {}",
        plan.kind,
        plan.file.display()
    );
    for note in &plan.notes {
        println!("  Note: {note}");
    }
    for blocker in &plan.blockers {
        println!("  First: {blocker}");
    }
    println!("To enable it:");
    for command in &plan.commands {
        println!("  {command}");
    }
    if !plan.blockers.is_empty() || !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("Run these now? [Y/n] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if !matches!(answer.trim(), "" | "y" | "Y" | "yes") {
        return Ok(false);
    }
    for command in &plan.commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .with_context(|| format!("run {command}"))?;
        if !status.success() {
            bail!("`{command}` failed; nothing after it ran. Fix it and run setup again.");
        }
    }
    Ok(true)
}

// ---- Tailscale -----------------------------------------------------------------

fn tailscale() -> Option<PathBuf> {
    if have("tailscale") {
        return Some(PathBuf::from("tailscale"));
    }
    let app = PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale");
    app.is_file().then_some(app)
}

/// Serves the loopback port on this machine's tailnet name over HTTPS.
/// Returns the public URL.
pub fn tailscale_serve(port: u16) -> Result<String> {
    let Some(bin) = tailscale() else {
        bail!(
            "Tailscale is not installed. Install it (https://tailscale.com/download), sign in, \
             then run this again."
        );
    };
    let status = Command::new(&bin)
        .args(["status", "--json"])
        .output()
        .context("run tailscale status")?;
    if !status.status.success() {
        bail!("Tailscale is not running or not signed in: run `tailscale up` first.");
    }
    let json: serde_json::Value =
        serde_json::from_slice(&status.stdout).context("read tailscale status")?;
    let name = json["Self"]["DNSName"]
        .as_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string();
    if name.is_empty() {
        bail!("Tailscale has no DNS name for this machine: turn on MagicDNS for your tailnet.");
    }
    let serve = Command::new(&bin)
        .args(["serve", "--bg", &format!("http://127.0.0.1:{port}")])
        .output()
        .context("run tailscale serve")?;
    if !serve.status.success() {
        let error = String::from_utf8_lossy(&serve.stderr);
        if error.contains("denied") || error.contains("operator") {
            bail!(
                "Tailscale needs permission to serve for this user. Run once:\n  \
                 sudo tailscale set --operator=$USER\nthen run setup again."
            );
        }
        bail!(
            "tailscale serve failed: {}\nHTTPS certificates must be on for the tailnet \
             (admin console → DNS → HTTPS Certificates).",
            error.trim()
        );
    }
    Ok(format!("https://{name}"))
}

// ---- after -------------------------------------------------------------------

/// Whether `url` answers as a KeyLease server.
pub async fn answers(url: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    else {
        return false;
    };
    match client.get(format!("{url}/healthz")).send().await {
        Ok(response) => response
            .text()
            .await
            .is_ok_and(|body| body.contains("\"keylease-server\"")),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_host_names() {
        assert_eq!(
            valid_domain("Keys.Example.com.").unwrap(),
            "keys.example.com"
        );
        assert_eq!(
            valid_domain("https://keys.example.com/").unwrap(),
            "keys.example.com"
        );
        for bad in [
            "localhost",
            "keys example.com",
            "-a.example.com",
            "a..b",
            "a_b.com",
            "",
        ] {
            assert!(valid_domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dns_is_classified() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let here = ip("203.0.113.7");
        assert_eq!(classify(&[here], |a| a == here), Dns::Here);
        assert_eq!(
            classify(&[ip("104.21.3.4"), ip("172.67.1.2")], |_| false),
            Dns::Cloudflare
        );
        assert_eq!(classify(&[ip("2606:4700::1")], |_| false), Dns::Cloudflare);
        assert_eq!(
            classify(&[ip("198.51.100.1")], |_| false),
            Dns::Elsewhere(vec![ip("198.51.100.1")])
        );
        assert_eq!(classify(&[], |_| true), Dns::Missing);
        assert!(!is_cloudflare(ip("173.208.50.160")));
    }

    #[test]
    fn site_files_proxy_to_loopback() {
        let caddy = caddy_site("keys.example.com", 8080, None);
        assert!(caddy.contains("https://keys.example.com {"));
        assert!(caddy.contains("reverse_proxy 127.0.0.1:8080"));
        assert!(!caddy.contains("tls "));
        let with_tls = caddy_site(
            "keys.example.com",
            8080,
            Some(&TlsFiles {
                cert: "/etc/caddy/o.pem".into(),
                key: "/etc/caddy/o.key".into(),
            }),
        );
        assert!(with_tls.contains("\ttls /etc/caddy/o.pem /etc/caddy/o.key\n"));
        let nginx = nginx_site("keys.example.com", 9000);
        assert!(nginx.contains("server_name keys.example.com;"));
        assert!(nginx.contains("proxy_pass http://127.0.0.1:9000;"));
    }
}
