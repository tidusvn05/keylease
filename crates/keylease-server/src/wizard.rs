//! The questions `keylease-server setup` asks at a terminal when no address
//! was given: where devices will reach the server, and what that needs
//! (DNS, a web server, certificates). Every answer maps to a setup option,
//! so a script can pass the same thing with flags instead.

use crate::expose::{self, Dns, TlsFiles};
use anyhow::{Result, bail};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
    process::Command,
};

/// Where devices reach the server.
pub enum Address {
    Domain { name: String, tls: Option<TlsFiles> },
    Tailscale,
    Local,
}

/// Whether setup can ask questions.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn read_line() -> Result<String> {
    std::io::stdout().flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("setup was cancelled (no more input)");
    }
    Ok(line.trim().to_string())
}

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    read_line()
}

pub fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [Y/n] ");
    Ok(matches!(
        read_line()?.to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

fn choose(prompt: &str, options: &[&str], default: usize) -> Result<usize> {
    if !prompt.is_empty() {
        println!("{prompt}");
    }
    for (index, option) in options.iter().enumerate() {
        println!("  {}) {option}", index + 1);
    }
    loop {
        let answer = ask(&format!("Choose 1-{} [{}]: ", options.len(), default + 1))?;
        if answer.is_empty() {
            return Ok(default);
        }
        if let Ok(number) = answer.parse::<usize>()
            && (1..=options.len()).contains(&number)
        {
            return Ok(number - 1);
        }
    }
}

fn step(title: &str) {
    println!();
    println!("== {title}");
}

/// Asks where devices will reach the server and prepares what that needs.
pub fn choose_address() -> Result<Address> {
    println!();
    println!("KeyLease server setup. Answer a few questions; Enter takes the default.");
    step("Where will your devices reach this server?");
    let public = expose::outbound_ip();
    let options = [
        "A domain name with HTTPS (a server with a public address)",
        "Tailscale: only your own devices, no public address needed",
        "Only this machine for now (reach it over an SSH tunnel)",
    ];
    match choose("", &options, if public.is_some() { 0 } else { 1 })? {
        0 => domain(public),
        1 => {
            tailscale_ready()?;
            Ok(Address::Tailscale)
        }
        _ => Ok(Address::Local),
    }
}

fn domain(public: Option<std::net::IpAddr>) -> Result<Address> {
    let name = loop {
        match expose::valid_domain(&ask("Domain name (e.g. keys.example.com): ")?) {
            Ok(name) => break name,
            Err(error) => println!("  {error}"),
        }
    };

    step("DNS");
    loop {
        let dns = expose::check_dns(&name);
        match &dns {
            Dns::Here => {
                println!("  {name} points to this machine.");
                break;
            }
            Dns::Cloudflare => {
                println!("  {name} goes through Cloudflare's proxy.");
                break;
            }
            Dns::Elsewhere(addresses) => println!(
                "  {name} points to {}, which is not an address of this machine.",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Dns::Missing => println!("  {name} does not resolve yet."),
        }
        match public {
            Some(ip) => println!(
                "  Add a DNS record at your DNS provider:  {} record  {name}  →  {ip}",
                if ip.is_ipv4() { "A" } else { "AAAA" }
            ),
            None => {
                println!("  Add an A record for {name} pointing to this machine's public address.")
            }
        }
        let answer = ask("  Press Enter to check again, or type c to continue anyway: ")?;
        if answer.eq_ignore_ascii_case("c") {
            break;
        }
    }

    step("Web server for HTTPS");
    let mut caddyfile = expose::caddyfile();
    if caddyfile.is_none() && !expose::has_nginx() {
        println!(
            "  Neither Caddy nor nginx is installed. Caddy gets and renews the certificate by itself."
        );
        match expose::caddy_install_command() {
            Some(command) if confirm(&format!("  Install Caddy now ({command})?"))? => {
                run(&command)?;
                caddyfile = expose::caddyfile();
                if caddyfile.is_none() {
                    bail!("Caddy did not install; install it, then run setup again");
                }
            }
            Some(command) => bail!("install Caddy ({command}), then run setup again"),
            None => {
                bail!("install Caddy (https://caddyserver.com/docs/install), then run setup again")
            }
        }
    }
    let mut tls = None;
    match &caddyfile {
        Some(file) => {
            println!("  Found Caddy ({}).", file.display());
            if expose::auto_https_off(file) {
                println!(
                    "  This Caddy has automatic HTTPS turned off, so it needs the certificate \
                     files for {name}."
                );
                tls = Some(certificate(file, &name)?);
            }
        }
        None => println!("  Found nginx; certbot will get the certificate."),
    }
    Ok(Address::Domain { name, tls })
}

pub fn certificate(caddyfile: &std::path::Path, name: &str) -> Result<TlsFiles> {
    let examples = expose::tls_examples(caddyfile);
    let mut options: Vec<String> = examples
        .iter()
        .map(|tls| format!("Reuse {} (another site uses it)", tls.cert.display()))
        .collect();
    options.push("Other certificate files".into());
    let labels: Vec<&str> = options.iter().map(String::as_str).collect();
    let picked = choose(
        &format!(
            "  Which certificate covers {name}? (A Cloudflare origin certificate for \
             *.{} covers it.)",
            name.split_once('.').map_or(name, |(_, parent)| parent)
        ),
        &labels,
        0,
    )?;
    if let Some(tls) = examples.into_iter().nth(picked) {
        return Ok(tls);
    }
    let cert = PathBuf::from(ask("  Certificate file (PEM): ")?);
    let key = PathBuf::from(ask("  Private key file (PEM): ")?);
    Ok(TlsFiles { cert, key })
}

fn tailscale_ready() -> Result<()> {
    let installed = Command::new("sh")
        .arg("-c")
        .arg("command -v tailscale")
        .output()
        .is_ok_and(|out| out.status.success())
        || std::path::Path::new("/Applications/Tailscale.app").exists();
    if !installed {
        bail!(
            "Tailscale is not installed. Install it (https://tailscale.com/download), sign in \
             with `tailscale up`, then run setup again."
        );
    }
    Ok(())
}

/// Runs a shell line at the terminal (it may ask for a sudo password).
pub fn run(command: &str) -> Result<()> {
    println!("  $ {command}");
    let status = Command::new("sh").arg("-c").arg(command).status()?;
    if !status.success() {
        bail!("`{command}` failed");
    }
    Ok(())
}
