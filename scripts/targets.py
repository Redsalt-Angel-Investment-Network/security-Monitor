"""Change which sites the monitor checks, without re-running setup.

    python scripts/targets.py list
    python scripts/targets.py add https://nunufunds.com https://api.nunufunds.com
    python scripts/targets.py remove https://dev.nunufunds.com

Edits SM_CHECK_URLS in .env (other settings are left untouched), then restarts
the web checker container so the change takes effect and a fresh round runs
straight away. Pass --no-restart to only edit .env.

Only add sites you own or have permission to test.
"""
import argparse
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ENV = Path(__file__).resolve().parent.parent / ".env"
KEY = "SM_CHECK_URLS"


def normalize(url: str) -> str:
    url = url.strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SystemExit(f"Not a valid web address: {url!r}")
    return f"{parts.scheme}://{parts.netloc.lower()}{parts.path}"


def read_lines() -> list[str]:
    if not ENV.exists():
        raise SystemExit("No .env yet: run `python scripts/setup.py` first.")
    return ENV.read_text(encoding="utf-8").splitlines()


def current(lines: list[str]) -> list[str]:
    for line in lines:
        if line.startswith(KEY + "="):
            return [u.strip() for u in line.split("=", 1)[1].split(",") if u.strip()]
    return []


def write(lines: list[str], urls: list[str]) -> None:
    new = f"{KEY}={','.join(urls)}"
    out, done = [], False
    for line in lines:
        if line.startswith(KEY + "="):
            out.append(new)
            done = True
        else:
            out.append(line)
    if not done:
        out.append(new)
    ENV.write_text("\n".join(out) + "\n", encoding="utf-8")


def restart() -> None:
    print("Restarting the web checker so it picks up the change...")
    cmd = ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "webcheck"]
    try:
        subprocess.run(cmd, cwd=ENV.parent, check=True)
    except (OSError, subprocess.CalledProcessError):
        print("Couldn't restart it automatically. Run:\n  " + " ".join(cmd))
        return
    print("Done. Watch the new round with:  docker compose logs -f webcheck")


def main() -> None:
    p = argparse.ArgumentParser(description="List, add or remove checked sites.")
    p.add_argument("action", choices=["list", "add", "remove"])
    p.add_argument("urls", nargs="*")
    p.add_argument("--no-restart", action="store_true", help="only edit .env")
    args = p.parse_args()

    lines = read_lines()
    urls = current(lines)

    if args.action == "list":
        print("\n".join(urls) if urls else "(no sites configured)")
        return
    if not args.urls:
        p.error(f"give at least one URL to {args.action}")

    given = [normalize(u) for u in args.urls]
    if args.action == "add":
        added = [u for u in given if u not in urls]
        urls += added
        print("Added: " + (", ".join(added) or "nothing new"))
    else:
        missing = [u for u in given if u not in urls]
        if missing:
            print("Not in the list: " + ", ".join(missing))
        urls = [u for u in urls if u not in given]
        if not urls:
            raise SystemExit("Refusing to remove every site: the checker needs at least one.")

    write(lines, urls)
    print("Now checking:\n  " + "\n  ".join(urls))
    if not args.no_restart:
        restart()


if __name__ == "__main__":
    sys.exit(main())
