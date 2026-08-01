#!/usr/bin/env python3
"""Build immutable cloud-init snippets and a self-contained Proxmox script."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

from render_profiles import CONFIG, CONFIG_FILE, LOCAL_CONFIG, PROFILES, ROOT, render


REPOSITORY = ROOT.parent
USER_DATA_TEMPLATE = ROOT / "templates" / "proxmox-user-data.yml.tmpl"
COMMAND_TEMPLATE = ROOT / "templates" / "proxmox-create-command.sh.tmpl"
IMAGE_BUILD = "20260722-2547"
IMAGE_SHA512 = (
    "735d1b2d0ef265a0c2323fdaa7d46e7bd7a1b984f73e8a785e638034bf07876"
    "e26374a9d809d713501270c071b3464d2ada0c5589f07742b95ed853cc6d48f45"
)
IMAGE_NAME = f"debian-13-genericcloud-amd64-{IMAGE_BUILD}.qcow2"
IMAGE_URL = (
    f"https://cloud.debian.org/images/cloud/trixie/{IMAGE_BUILD}/{IMAGE_NAME}"
)
TEST_SSH_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIB4YrFhM2yPVzO+3kI14mYw3V91sCi1qdtB2bWjBv7E4 "
    "bundle-validation@example.invalid"
)

PROFILE_SUFFIXES = {
    "deb_13_plain.yml": "plain",
    "deb_13_plain_syslog.yml": "plain-syslog",
    "deb_13_docker.yml": "docker",
    "deb_13_docker_syslog.yml": "docker-syslog",
}


@dataclass(frozen=True)
class VendorArtifact:
    vmid: int
    template_name: str
    filename: str
    digest: str
    content: str
    needs_appdata: bool


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def run(command: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        fail(f"command failed: {shlex.join(command)}")
    return result.stdout


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def render_user_data(public_key: str) -> str:
    template = USER_DATA_TEMPLATE.read_text(encoding="utf-8")
    marker = "@@SSH_PUBLIC_KEY@@"
    if template.count(marker) != 1:
        fail("user-data template must contain exactly one SSH key marker")
    return template.replace(marker, public_key)


def render_command(
    *,
    vendor: VendorArtifact,
    user_name: str,
    user_hash: str,
) -> str:
    replacements = {
        "@@VMID@@": str(vendor.vmid),
        "@@NAME@@": vendor.template_name,
        "@@NEEDS_APPDATA@@": str(int(vendor.needs_appdata)),
        "@@CPU@@": CONFIG["CPU"],
        "@@MEM_MIN@@": CONFIG["MEM_MIN"],
        "@@MEM_MAX@@": CONFIG["MEM_MAX"],
        "@@BRIDGE@@": CONFIG["BRIDGE"],
        "@@VM_STORAGE_NAME@@": CONFIG["VM_STORAGE_NAME"],
        "@@SNIPPET_STORAGE_NAME@@": CONFIG["SNIPPET_STORAGE_NAME"],
        "@@PROXMOX_SNIPPET_PATH@@": CONFIG["PROXMOX_SNIPPET_PATH"],
        "@@ISO_STORAGE_PATH@@": CONFIG["ISO_STORAGE_PATH"],
        "@@APPDATA_DISK_SIZE@@": CONFIG["APPDATA_DISK_SIZE"],
        "@@APPDATA_SERIAL@@": CONFIG["APPDATA_SERIAL"],
        "@@APPDATA_WWN@@": CONFIG["APPDATA_WWN"],
        "@@VENDOR_SNIPPET_NAME@@": vendor.filename,
        "@@VENDOR_SHA256@@": vendor.digest,
        "@@USER_SNIPPET_NAME@@": user_name,
        "@@USER_SHA256@@": user_hash,
        "@@IMAGE_NAME@@": IMAGE_NAME,
        "@@IMAGE_SHA512@@": IMAGE_SHA512,
        "@@IMAGE_URL@@": IMAGE_URL,
    }
    content = COMMAND_TEMPLATE.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        content = content.replace(marker, shlex.quote(value))
    unresolved = sorted(set(re.findall(r"@@[A-Z0-9_]+@@", content)))
    if unresolved:
        fail(f"unresolved Proxmox command markers: {unresolved}")
    return content


def validate_rendered(
    vendors: tuple[VendorArtifact, ...], user_data: str, command: str
) -> None:
    cloud_init = shutil.which("cloud-init")
    with tempfile.TemporaryDirectory(prefix="cloud-init-bundle-check.") as temp_dir:
        temp_path = Path(temp_dir)
        user_path = temp_path / "user.yml"
        user_path.write_text(user_data, encoding="utf-8")
        if cloud_init:
            for vendor in vendors:
                vendor_path = temp_path / vendor.filename
                vendor_path.write_text(vendor.content, encoding="utf-8")
                run([cloud_init, "schema", "--config-file", str(vendor_path)])
            run([cloud_init, "schema", "--config-file", str(user_path)])
    run(["bash", "-n"], input_text=command)
    shellcheck = shutil.which("shellcheck")
    if shellcheck:
        run([shellcheck, "--shell", "bash", "-"], input_text=command)


def install_artifact(directory: Path, name: str, content: str, mode: int) -> Path:
    destination = directory / name
    encoded = content.encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{name}.", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as artifact:
            artifact.write(encoded)
            artifact.flush()
            os.fsync(artifact.fileno())
        temporary.chmod(mode)
        os.replace(temporary, destination)
        if not destination.exists() or destination.read_bytes() != encoded:
            fail(f"artifact installation verification failed: {destination}")
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def read_public_key() -> str:
    key_path = Path(CONFIG["SSH_PUBLIC_KEY_FILE"]).expanduser()
    if not key_path.is_absolute():
        key_path = CONFIG_FILE.parent / key_path
    if not key_path.is_file():
        fail(f"SSH public key is missing: {key_path}")
    lines = key_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or not lines[0]:
        fail("SSH_PUBLIC_KEY_FILE must contain exactly one public key line")
    run(["ssh-keygen", "-l", "-f", str(key_path)])
    if "-cert-v01@openssh.com " in lines[0]:
        fail("signed OpenSSH certificates require trusted-CA server configuration")
    return lines[0]


def vendor_artifacts() -> tuple[VendorArtifact, ...]:
    vmid_start = int(CONFIG["VMID_START"])
    artifacts: list[VendorArtifact] = []
    for offset, profile in enumerate(PROFILES):
        vendor_data = render(profile)
        vendor_hash = sha256(vendor_data)
        suffix = PROFILE_SUFFIXES[profile.output]
        artifacts.append(
            VendorArtifact(
                vmid=vmid_start + offset,
                template_name=f"{CONFIG['NAME_PREFIX']}-{suffix}-template",
                filename=f"{CONFIG['NAME_PREFIX']}-{suffix}-template-vendor.yml",
                digest=vendor_hash,
                content=vendor_data,
                needs_appdata=profile.docker,
            )
        )
    return tuple(artifacts)


def validate_only() -> None:
    user_data = render_user_data(TEST_SSH_PUBLIC_KEY)
    user_hash = sha256(user_data)
    vendors = vendor_artifacts()
    user_name = f"{CONFIG['NAME_PREFIX']}-admin-user.yml"
    for vendor in vendors:
        command = render_command(
            vendor=vendor,
            user_name=user_name,
            user_hash=user_hash,
        )
        validate_rendered((vendor,), user_data, command)
    print(f"Validated bundle configuration: {CONFIG_FILE}")


def build() -> None:
    if "CLOUD_INIT_ENV_FILE" not in os.environ and not LOCAL_CONFIG.is_file():
        fail(
            "copy cloud-init/tools/.env.example to cloud-init/tools/.env and edit it first"
        )
    for command in ("bash", "ssh-keygen"):
        if not shutil.which(command):
            fail(f"required local command is missing: {command}")

    run([sys.executable, str(ROOT / "tools" / "validate_profiles.py")])

    public_key = read_public_key()
    user_data = render_user_data(public_key)
    user_hash = sha256(user_data)
    vendors = vendor_artifacts()
    user_name = f"{CONFIG['NAME_PREFIX']}-admin-user.yml"
    commands = tuple(
        (
            f"create-{vendor.template_name}.sh",
            render_command(
                vendor=vendor,
                user_name=user_name,
                user_hash=user_hash,
            ),
            vendor,
        )
        for vendor in vendors
    )
    for _, command, vendor in commands:
        validate_rendered((vendor,), user_data, command)

    output_directory = Path(CONFIG["ARTIFACT_OUTPUT_DIR"]).expanduser()
    if not output_directory.is_absolute():
        output_directory = REPOSITORY / output_directory
    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        fail(f"ARTIFACT_OUTPUT_DIR is not a directory: {output_directory}")
    if not os.access(output_directory, os.W_OK):
        fail(f"ARTIFACT_OUTPUT_DIR is not writable: {output_directory}")

    yaml_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    paths = [
        install_artifact(output_directory, vendor.filename, vendor.content, yaml_mode)
        for vendor in vendors
    ]
    paths.extend(
        (
            install_artifact(
                output_directory,
                user_name,
                user_data,
                yaml_mode,
            ),
        )
    )

    command_mode = (
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    paths.extend(
        install_artifact(output_directory, name, command, command_mode)
        for name, command, _ in commands
    )

    print("Built template bundle from the current local files")
    for path in paths:
        print(path)
    print("Copy the five YAML files and whichever template scripts you want.")
    print("Run any one of these commands on Proxmox:")
    for command_name, _, _ in commands:
        print(f"bash {Path(CONFIG['PROXMOX_SNIPPET_PATH']) / command_name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--validate",
        action="store_true",
        help="validate configuration and templates without building artifacts",
    )
    arguments = parser.parse_args()
    if arguments.validate:
        validate_only()
    else:
        build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
