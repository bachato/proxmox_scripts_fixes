#!/usr/bin/env python3
"""Render the Debian 13 cloud-init profiles from one local template."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import shlex
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "deb_13.yml.tmpl"
DOCKER_KEY = ROOT / "assets" / "docker-release.asc"
LOCAL_CONFIG = ROOT / "tools" / ".env"
EXAMPLE_CONFIG = ROOT / "tools" / ".env.example"

SITE_KEYS = {
    "BRIDGE",
    "SYSLOG_SERVER",
    "SYSLOG_PORT",
    "FAIL2BAN_IGNORE_IPS",
    "APPDATA_WWN",
    "APPDATA_SERIAL",
}
BUILD_KEYS = {
    "VMID_START",
    "NAME_PREFIX",
    "SSH_PUBLIC_KEY_FILE",
    "ARTIFACT_OUTPUT_DIR",
    "SNIPPET_STORAGE_NAME",
    "PROXMOX_SNIPPET_PATH",
    "ISO_STORAGE_PATH",
    "VM_STORAGE_NAME",
    "CPU",
    "MEM_MIN",
    "MEM_MAX",
    "APPDATA_DISK_SIZE",
}
CONFIG_KEYS = SITE_KEYS | BUILD_KEYS


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


def _config_path() -> Path:
    override = os.environ.get("CLOUD_INIT_ENV_FILE")
    if override:
        return Path(override).expanduser().resolve()
    if LOCAL_CONFIG.exists():
        return LOCAL_CONFIG
    return EXAMPLE_CONFIG


CONFIG_FILE = _config_path()


def _parse_config_value(raw_value: str, line_number: int) -> str:
    try:
        values = shlex.split(raw_value, comments=False, posix=True)
    except ValueError as error:
        raise ValueError(f"{CONFIG_FILE}:{line_number}: {error}") from error
    if len(values) != 1 or not values[0]:
        raise ValueError(
            f"{CONFIG_FILE}:{line_number}: values containing spaces must be quoted"
        )
    return values[0]


def _valid_hostname(value: str) -> bool:
    if len(value) > 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def load_config() -> dict[str, str]:
    if not CONFIG_FILE.is_file():
        raise ValueError(
            f"Configuration file is missing: {CONFIG_FILE}; copy .env.example to .env"
        )

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        CONFIG_FILE.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: expected KEY=value")
        key, raw_value = match.groups()
        if key not in CONFIG_KEYS:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: unknown key {key}")
        if key in values:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: duplicate key {key}")
        values[key] = _parse_config_value(raw_value, line_number)

    missing = sorted(CONFIG_KEYS - values.keys())
    if missing:
        raise ValueError(f"{CONFIG_FILE}: missing required keys: {missing}")

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", values["BRIDGE"]):
        raise ValueError(f"{CONFIG_FILE}: BRIDGE contains unsupported characters")

    try:
        ipaddress.ip_address(values["SYSLOG_SERVER"])
    except ValueError:
        if not _valid_hostname(values["SYSLOG_SERVER"]):
            raise ValueError(
                f"{CONFIG_FILE}: SYSLOG_SERVER is not a valid IP address or hostname"
            )

    try:
        syslog_port = int(values["SYSLOG_PORT"])
    except ValueError as error:
        raise ValueError(f"{CONFIG_FILE}: SYSLOG_PORT must be an integer") from error
    if not 1 <= syslog_port <= 65535:
        raise ValueError(f"{CONFIG_FILE}: SYSLOG_PORT must be between 1 and 65535")

    ignore_ips = values["FAIL2BAN_IGNORE_IPS"].split()
    if not ignore_ips:
        raise ValueError(f"{CONFIG_FILE}: FAIL2BAN_IGNORE_IPS cannot be empty")
    for network in ignore_ips:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as error:
            raise ValueError(
                f"{CONFIG_FILE}: invalid FAIL2BAN_IGNORE_IPS entry {network}"
            ) from error
    if "127.0.0.1/8" not in ignore_ips or "::1" not in ignore_ips:
        raise ValueError(
            f"{CONFIG_FILE}: FAIL2BAN_IGNORE_IPS must include IPv4 and IPv6 loopback"
        )

    if not re.fullmatch(r"0x[0-9A-Fa-f]{16}", values["APPDATA_WWN"]):
        raise ValueError(
            f"{CONFIG_FILE}: APPDATA_WWN must be 0x followed by 16 hex digits"
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", values["APPDATA_SERIAL"]):
        raise ValueError(f"{CONFIG_FILE}: APPDATA_SERIAL contains unsupported characters")

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,48}", values["NAME_PREFIX"]
    ):
        raise ValueError(f"{CONFIG_FILE}: NAME_PREFIX contains unsupported characters")
    for key in ("SNIPPET_STORAGE_NAME", "VM_STORAGE_NAME"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", values[key]):
            raise ValueError(f"{CONFIG_FILE}: {key} contains unsupported characters")
    for key in (
        "PROXMOX_SNIPPET_PATH",
        "ISO_STORAGE_PATH",
    ):
        if not Path(values[key]).expanduser().is_absolute():
            raise ValueError(f"{CONFIG_FILE}: {key} must be an absolute path")
    for key in ("VMID_START", "CPU", "MEM_MIN", "MEM_MAX", "APPDATA_DISK_SIZE"):
        if not values[key].isdigit() or int(values[key]) <= 0:
            raise ValueError(f"{CONFIG_FILE}: {key} must be a positive integer")
    if int(values["VMID_START"]) + len(PROFILES) - 1 > 999999999:
        raise ValueError(f"{CONFIG_FILE}: generated VM IDs exceed Proxmox limits")
    if int(values["MEM_MIN"]) > int(values["MEM_MAX"]):
        raise ValueError(f"{CONFIG_FILE}: MEM_MIN cannot exceed MEM_MAX")

    return values


CONFIG = load_config()
SITE = {key: CONFIG[key] for key in SITE_KEYS}


def render(profile: Profile) -> str:
    flags = {"docker": profile.docker, "syslog": profile.syslog}
    replacements = {
        "@@PROFILE_NAME@@": profile.name,
        "@@FAIL2BAN_IGNORE_IPS@@": SITE["FAIL2BAN_IGNORE_IPS"],
        "@@SYSLOG_SERVER@@": SITE["SYSLOG_SERVER"],
        "@@SYSLOG_PORT@@": SITE["SYSLOG_PORT"],
        "@@APPDATA_WWN@@": SITE["APPDATA_WWN"],
        "@@APPDATA_SERIAL@@": SITE["APPDATA_SERIAL"],
    }
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

        line = raw_line
        for placeholder, value in replacements.items():
            line = line.replace(placeholder, value)
        if "@@DOCKER_GPG_KEY@@" in line:
            prefix = line[: line.index("@@DOCKER_GPG_KEY@@")]
            output.extend(
                f"{prefix}{key_line}" if key_line else prefix.rstrip()
                for key_line in DOCKER_KEY.read_text(encoding="utf-8").splitlines()
            )
        else:
            unresolved = re.findall(r"@@[A-Z0-9_]+@@", line)
            if unresolved:
                raise ValueError(f"Unresolved template placeholders: {unresolved}")
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
    output_directory = ROOT / "build"
    if not check:
        output_directory.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        expected = render(profile)
        if check:
            print(f"rendered in memory: {profile.output}")
        else:
            destination = output_directory / profile.output
            destination.write_text(expected, encoding="utf-8")
            print(f"rendered {destination.relative_to(ROOT.parent)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="render every profile in memory without writing preview files",
    )
    args = parser.parse_args()
    return check_or_write(args.check)


if __name__ == "__main__":
    sys.exit(main())
