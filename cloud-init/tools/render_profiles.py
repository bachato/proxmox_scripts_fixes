#!/usr/bin/env python3
"""Render the committed Debian 13 cloud-init profiles from one template."""

from __future__ import annotations

import argparse
import difflib
from dataclasses import dataclass
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "deb_13.yml.tmpl"
DOCKER_KEY = ROOT / "assets" / "docker-release.asc"


@dataclass(frozen=True)
class Profile:
    output: str
    name: str
    docker: bool
    syslog: bool


PROFILES = (
    Profile("deb_13_plain.yml", "Debian 13 plain", docker=False, syslog=False),
    Profile(
        "deb_13_plain_syslog.yml",
        "Debian 13 plain with remote syslog",
        docker=False,
        syslog=True,
    ),
    Profile("deb_13_docker.yml", "Debian 13 with Docker", docker=True, syslog=False),
    Profile(
        "deb_13_docker_syslog.yml",
        "Debian 13 with Docker and remote syslog",
        docker=True,
        syslog=True,
    ),
)


def render(profile: Profile) -> str:
    flags = {"docker": profile.docker, "syslog": profile.syslog}
    output: list[str] = []
    active_stack = [True]

    for raw_line in TEMPLATE.read_text(encoding="utf-8").splitlines():
        directive = raw_line.strip()
        if directive.startswith("#% if "):
            flag = directive.removeprefix("#% if ").strip()
            if flag not in flags:
                raise ValueError(f"Unknown template flag: {flag}")
            active_stack.append(active_stack[-1] and flags[flag])
            continue
        if directive == "#% endif":
            if len(active_stack) == 1:
                raise ValueError("Unexpected template endif")
            active_stack.pop()
            continue
        if not active_stack[-1]:
            continue

        line = raw_line.replace("@@PROFILE_NAME@@", profile.name)
        if "@@DOCKER_GPG_KEY@@" in line:
            prefix = line[: line.index("@@DOCKER_GPG_KEY@@")]
            output.extend(
                f"{prefix}{key_line}" if key_line else prefix.rstrip()
                for key_line in DOCKER_KEY.read_text(encoding="utf-8").splitlines()
            )
        else:
            output.append(line)

    if len(active_stack) != 1:
        raise ValueError("Unclosed template conditional")

    compacted: list[str] = []
    for line in output:
        if not line and compacted and not compacted[-1]:
            continue
        compacted.append(line)

    return "\n".join(compacted).rstrip() + "\n"


def check_or_write(check: bool) -> int:
    changed = False
    for profile in PROFILES:
        destination = ROOT / profile.output
        expected = render(profile)
        actual = destination.read_text(encoding="utf-8") if destination.exists() else ""
        if actual == expected:
            continue

        changed = True
        if check:
            diff = difflib.unified_diff(
                actual.splitlines(),
                expected.splitlines(),
                fromfile=str(destination),
                tofile=f"{destination} (generated)",
                lineterm="",
            )
            print("\n".join(diff))
        else:
            destination.write_text(expected, encoding="utf-8")
            print(f"rendered {destination.relative_to(ROOT.parent)}")

    return 1 if check and changed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail and print a diff when committed profiles are stale",
    )
    args = parser.parse_args()
    return check_or_write(args.check)


if __name__ == "__main__":
    sys.exit(main())
