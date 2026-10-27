#!/usr/bin/env python3
"""Release helpers for KeyLease (the procedure is in docs/releasing.md).

    scripts/release.py version 0.2.0       set the workspace version, every internal dependency
                                           and Cargo.lock (0.2.0-rc.1 works too)
    scripts/release.py order               print the publishable crates in publishing order
    scripts/release.py pending             print the crates whose version is not on crates.io yet,
                                           and check names and ownership
    scripts/release.py publish [--dry-run [--allow-dirty] | --no-new]
                                           publish every publishable crate to crates.io, in order
    scripts/release.py trustpub OWNER/REPO [--workflow F] [--environment E] [--crates a,b] [--only]
                                           set up crates.io Trusted Publishing for the crates

`publish` can be run again after a failure: versions already on crates.io are skipped, and a
yanked version is never reused. When crates.io rate-limits (HTTP 429, about one new crate every
10 minutes after a short burst) it waits for the time crates.io gives and retries. With
`--no-new` (the release workflow, whose Trusted Publishing token cannot create crates) it stops
before publishing anything if a crate is not on crates.io yet.

`trustpub` needs a crates.io API token with the `trusted-publishing` scope: CRATES_IO_TOKEN, or
the token saved by `cargo login`. It never prints the token. Running it again changes nothing.
"""

import email.utils
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-rc\.\d+)?$")
OWNER = "tidusvn05"  # the crates.io user that must own every published crate
USER_AGENT = "keylease-release (https://github.com/tidusvn05/keylease)"


def metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def publish_order():
    """Publishable workspace crates, dependencies (dev-dependencies too) before dependents."""
    everything = {p["name"]: p for p in metadata()["packages"]}
    packages = {n: p for n, p in everything.items() if p.get("publish") != []}
    deps = {}
    for name, p in packages.items():
        internal = {d["name"] for d in p["dependencies"] if d["name"] in everything}
        internal.discard(name)
        private = sorted(internal - set(packages))
        if private:
            sys.exit(f"{name} depends on unpublishable {private}: publish them or drop the dependency")
        deps[name] = internal
    order, done = [], set()
    while len(order) < len(packages):
        ready = sorted(n for n in packages if n not in done and deps[n] <= done)
        if not ready:
            left = sorted(set(packages) - done)
            cycle = {n: sorted(deps[n] - done) for n in left}
            sys.exit(f"dependency cycle among {left}: {cycle}")
        order.extend(ready)
        done.update(ready)
    versions = {p["version"] for p in packages.values()}
    if len(versions) != 1:
        sys.exit(f"crates have different versions: {sorted(versions)}")
    return order, versions.pop()


def set_version(version):
    if not SEMVER.match(version):
        sys.exit(f"`{version}` is not a version like 0.2.0 or 0.2.0-rc.1")
    path = ROOT / "Cargo.toml"
    text, n = re.subn(
        r'(\[workspace\.package\][^\[]*?\nversion = )"[^"]*"', rf'\1"{version}"',
        path.read_text(), count=1,
    )
    if n != 1:
        sys.exit("no version in [workspace.package]")
    path.write_text(text)
    internal = 0
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        text, n = re.subn(
            r'(\{ path = "\.\./[^"]+", version = )"[^"]*"', rf'\1"{version}"', manifest.read_text()
        )
        manifest.write_text(text)
        internal += n
    subprocess.run(["cargo", "update", "--workspace", "--quiet"], cwd=ROOT, check=True)
    print(f"version {version} ({internal} internal dependencies)")


def index_entries(name):
    """Index entries of `name` on crates.io ({version: yanked}), or None for an unknown crate."""
    lower = name.lower()
    if len(lower) <= 2:
        prefix = str(len(lower))
    elif len(lower) == 3:
        prefix = f"3/{lower[0]}"
    else:
        prefix = f"{lower[:2]}/{lower[2:4]}"
    request = urllib.request.Request(f"https://index.crates.io/{prefix}/{lower}",
                                     headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            lines = response.read().decode().splitlines()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    entries = (json.loads(line) for line in lines if line.strip())
    return {e["vers"]: e.get("yanked", False) for e in entries}


def crates_io(method, path, token=None, body=None, missing_ok=False):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json",
               "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    data = None if body is None else json.dumps(body).encode()
    for _ in range(10):
        request = urllib.request.Request(f"https://crates.io/api/v1{path}", method=method,
                                         data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            if error.code == 429:
                wait = int(error.headers.get("Retry-After") or 60)
                print(f"  crates.io rate limit; retrying in {wait} s", flush=True)
                time.sleep(wait)
                continue
            detail = error.read().decode(errors="replace")
            sys.exit(f"crates.io {method} {path}: HTTP {error.code} {detail}")
    sys.exit(f"crates.io {method} {path}: still rate-limited")


def check_name(name):
    """None when `name` is free; otherwise the owners of the crate crates.io matches it to
    (crates.io treats `-` and `_` as the same)."""
    for candidate in {name, name.replace("-", "_"), name.replace("_", "-")}:
        found = crates_io("GET", f"/crates/{candidate}", missing_ok=True)
        if found:
            owners = crates_io("GET", f"/crates/{found['crate']['name']}/owners")
            return found["crate"]["name"], [u["login"] for u in owners.get("users", [])]
    return None


def pending():
    """Prints the crates still to publish. With GITHUB_OUTPUT set, also writes `count` and `new`
    (crates crates.io does not have at all: Trusted Publishing cannot create them)."""
    order, version = publish_order()
    todo, new, problems = [], [], []
    for name in order:
        entries = index_entries(name)
        if entries is None:
            taken = check_name(name)
            if taken:
                problems.append(f"{name}: crates.io already has {taken[0]} (owners {taken[1]})")
            new.append(name)
        else:
            if entries.get(version) is True:
                problems.append(f"{name} {version} is yanked: release a new version")
            owners = [u["login"] for u in
                      crates_io("GET", f"/crates/{name}/owners").get("users", [])]
            if OWNER not in owners:
                problems.append(f"{name}: owned by {owners}, not {OWNER}")
        if version not in (entries or {}):
            todo.append(name)
    for name in todo:
        print(f"{name} {version}" + (" (new crate)" if name in new else ""))
    if not todo:
        print(f"every crate is on crates.io at {version}")
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as out:
            out.write(f"count={len(todo)}\nnew={' '.join(new)}\n")
    if problems:
        sys.exit(1)


def cargo_token():
    """The crates.io token saved by `cargo login`, if any."""
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for name in ("credentials.toml", "credentials"):
        path = home / name
        if path.is_file():
            with open(path, "rb") as f:
                return tomllib.load(f).get("registry", {}).get("token", "")
    return ""


def trustpub(args):
    token = os.environ.get("CRATES_IO_TOKEN") or cargo_token()
    if not token:
        sys.exit("run `cargo login` (or set CRATES_IO_TOKEN) with a crates.io token that has the "
                 "`trusted-publishing` scope")
    if not args or "/" not in args[0]:
        sys.exit(__doc__)
    owner, repo = args[0].split("/", 1)
    options = {"--workflow": "release.yml", "--environment": "crates-io", "--crates": None}
    only = False
    rest = args[1:]
    while rest:
        flag = rest.pop(0)
        if flag == "--only":
            only = True
        elif flag in options and rest:
            options[flag] = rest.pop(0)
        else:
            sys.exit(__doc__)
    crates = options["--crates"].split(",") if options["--crates"] else publish_order()[0]
    environment = options["--environment"] or None
    for name in crates:
        existing = crates_io("GET", f"/trusted_publishing/github_configs?crate={name}", token)
        same = [
            c for c in existing.get("github_configs", [])
            if c["repository_owner"].lower() == owner.lower()
            and c["repository_name"].lower() == repo.lower()
            and c["workflow_filename"] == options["--workflow"]
            and c.get("environment") == environment
        ]
        if same:
            print(f"= {name}: already trusts {owner}/{repo} {options['--workflow']}")
        else:
            crates_io("POST", "/trusted_publishing/github_configs", token, {
                "github_config": {
                    "crate": name,
                    "repository_owner": owner,
                    "repository_name": repo,
                    "workflow_filename": options["--workflow"],
                    "environment": environment,
                }
            })
            print(f"+ {name}: trusts {owner}/{repo} {options['--workflow']}"
                  + (f" (environment {environment})" if environment else ""))
        if only:
            crates_io("PATCH", f"/crates/{name}", token, {"crate": {"trustpub_only": True}})
            print(f"  {name}: Trusted Publishing only")


def retry_after(output):
    """Seconds to wait from a crates.io 429 message ("Please try again after <date>")."""
    match = re.search(r"try again after ([^.]+?(?:GMT|UTC|\+0000))", output)
    if match:
        try:
            when = email.utils.parsedate_to_datetime(match.group(1))
            return max(30, int((when - datetime.now(timezone.utc)).total_seconds()) + 15)
        except (TypeError, ValueError):
            pass
    return 600


def publish(dry_run, allow_dirty=False, no_new=False):
    order, version = publish_order()
    if dry_run:
        # Before the first publish the dependencies are not on crates.io: cargo packages the
        # whole workspace against a local registry instead.
        command = ["cargo", "publish", "--workspace", "--dry-run", "--locked"]
        if allow_dirty:
            command.append("--allow-dirty")
        subprocess.run(command, cwd=ROOT, check=True)
        print(f"packaged {len(order)} crates at {version}: {' '.join(order)}")
        return
    if "-" in version:
        sys.exit(f"refusing to publish the pre-release version {version} to crates.io")
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, check=True,
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        sys.exit("the working tree is not clean; publish only from a clean checkout of the tag")
    entries = {name: index_entries(name) for name in order}
    yanked = [n for n, e in entries.items() if e and e.get(version) is True]
    if yanked:
        sys.exit(f"{version} is yanked for {yanked}: release a new version instead")
    new = [n for n, e in entries.items() if e is None]
    if new and no_new:
        sys.exit(f"not on crates.io yet: {' '.join(new)}. Trusted Publishing cannot create a "
                 f"crate: publish them by hand first (docs/releasing.md, 'A new crate'), then "
                 f"re-run this job")
    for name in order:
        if version in (entries[name] or {}):
            print(f"= {name} {version} is already on crates.io")
            continue
        command = ["cargo", "publish", "--locked", "-p", name]
        while True:
            print(f"> {' '.join(command)}", flush=True)
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            output = run.stdout + run.stderr
            if run.returncode == 0:
                break
            if "429" in output or "Too Many Requests" in output:
                wait = retry_after(output)
                print(f"  rate-limited by crates.io; retrying in {wait // 60} min {wait % 60} s",
                      flush=True)
                time.sleep(wait)
                continue
            if "already exists" in output:
                print(f"= {name} {version} is already on crates.io")
                break
            sys.stderr.write(output)
            sys.exit(f"publishing {name} failed; fix it and run this again")
    print(f"published {len(order)} crates at {version}")


def main():
    args = sys.argv[1:]
    if args[:1] == ["version"] and len(args) == 2:
        set_version(args[1])
    elif args == ["order"]:
        order, version = publish_order()
        print(f"{version}: " + " ".join(order))
    elif args == ["pending"]:
        pending()
    elif args[:1] == ["publish"] and args[1:] in ([], ["--dry-run"], ["--dry-run", "--allow-dirty"],
                                                  ["--no-new"]):
        publish(dry_run="--dry-run" in args, allow_dirty="--allow-dirty" in args,
                no_new="--no-new" in args)
    elif args[:1] == ["trustpub"]:
        trustpub(args[1:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
