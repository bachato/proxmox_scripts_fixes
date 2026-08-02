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
COMMAND_TEMPLATE = ROOT / "templates" / "proxmox-create-command.sh.tmpl"
BUNDLE_MARKER = ".cloud-init-bundle"
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


def render_command(
    *,
    vendor: VendorArtifact,
    public_key: str,
) -> str:
    replacements = {
        "@@VMID@@": str(vendor.vmid),
        "@@NAME@@": vendor.template_name,
        "@@NEEDS_APPDATA@@": str(int(vendor.needs_appdata)),
        "@@CPU@@": CONFIG["CPU"],
        "@@MEM_MIN@@": CONFIG["MEM_MIN"],
        "@@MEM_MAX@@": CONFIG["MEM_MAX"],
        "@@BRIDGE@@": CONFIG["BRIDGE"],
        "@@VLAN_TAG@@": CONFIG["VLAN_TAG"],
        "@@VM_STORAGE_NAME@@": CONFIG["VM_STORAGE_NAME"],
        "@@SNIPPET_STORAGE_NAME@@": CONFIG["SNIPPET_STORAGE_NAME"],
        "@@ISO_STORAGE_PATH@@": CONFIG["ISO_STORAGE_PATH"],
        "@@ROOT_DISK_SIZE@@": CONFIG["ROOT_DISK_SIZE"],
        "@@APPDATA_DISK_SIZE@@": CONFIG["APPDATA_DISK_SIZE"],
        "@@APPDATA_SERIAL@@": CONFIG["APPDATA_SERIAL"],
        "@@APPDATA_WWN@@": CONFIG["APPDATA_WWN"],
        "@@VENDOR_SNIPPET_NAME@@": vendor.filename,
        "@@VENDOR_SHA256@@": vendor.digest,
        "@@SSH_PUBLIC_KEY@@": public_key,
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
    vendors: tuple[VendorArtifact, ...], command: str
) -> None:
    cloud_init = shutil.which("cloud-init")
    with tempfile.TemporaryDirectory(prefix="cloud-init-bundle-check.") as temp_dir:
        temp_path = Path(temp_dir)
        if cloud_init:
            for vendor in vendors:
                vendor_path = temp_path / vendor.filename
                vendor_path.write_text(vendor.content, encoding="utf-8")
                run([cloud_init, "schema", "--config-file", str(vendor_path)])
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


def prepare_output_directory() -> Path:
    """Resolve ARTIFACT_OUTPUT_DIR and take ownership of it.

    The directory holds generated output and nothing else. A marker file
    records that a build owns it, so a mistyped path cannot scatter artifacts
    into a directory that holds real work, and a rebuild starts clean instead
    of leaving scripts behind from an earlier NAME_PREFIX for scp to pick up.
    """
    directory = Path(CONFIG["ARTIFACT_OUTPUT_DIR"]).expanduser()
    if not directory.is_absolute():
        directory = REPOSITORY / directory

    if directory.exists() and not directory.is_dir():
        fail(f"ARTIFACT_OUTPUT_DIR is not a directory: {directory}")
    if not directory.is_dir():
        try:
            directory.mkdir(parents=True)
        except OSError as error:
            fail(f"could not create ARTIFACT_OUTPUT_DIR {directory}: {error}")
    if not os.access(directory, os.W_OK):
        fail(f"ARTIFACT_OUTPUT_DIR is not writable: {directory}")

    marker = directory / BUNDLE_MARKER
    existing = sorted(directory.iterdir())
    if existing and not marker.is_file():
        fail(
            f"ARTIFACT_OUTPUT_DIR is not empty and has no {BUNDLE_MARKER} marker: "
            f"{directory}; point it at a directory dedicated to generated files"
        )
    for entry in existing:
        if entry == marker:
            continue
        if entry.is_dir() and not entry.is_symlink():
            fail(f"unexpected directory in the bundle output: {entry}")
        entry.unlink()

    marker.write_text(
        "Generated by cloud-init/tools/build_template_bundle.py.\n"
        "Every file here is rebuilt from scratch; do not keep anything in it.\n",
        encoding="utf-8",
    )
    return directory


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
    vendors = vendor_artifacts()
    for vendor in vendors:
        command = render_command(
            vendor=vendor,
            public_key=TEST_SSH_PUBLIC_KEY,
        )
        validate_rendered((vendor,), command)
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
    vendors = vendor_artifacts()
    commands = tuple(
        (
            f"create-{vendor.template_name}.sh",
            render_command(
                vendor=vendor,
                public_key=public_key,
            ),
            vendor,
        )
        for vendor in vendors
    )
    for _, command, vendor in commands:
        validate_rendered((vendor,), command)

    output_directory = prepare_output_directory()

    yaml_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    paths = [
        install_artifact(output_directory, vendor.filename, vendor.content, yaml_mode)
        for vendor in vendors
    ]
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
    print("Copy the four YAML files and whichever template scripts you want.")
    print(
        "From the snippets directory of "
        f"{CONFIG['SNIPPET_STORAGE_NAME']} on Proxmox, run any one of these:"
    )
    for command_name, _, _ in commands:
        print(f"bash {command_name}")


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
