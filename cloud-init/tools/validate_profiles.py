#!/usr/bin/env python3
"""Validate generated cloud-init profiles and their embedded configurations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

from render_profiles import PROFILES, ROOT, SITE, render


DOCKER_KEY_SHA256 = "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
DOCKER_KEY_FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
SUCCESS_MARKER = "/var/lib/cloud/instance/boot-success"
PRECHECK_MARKER = "/var/lib/cloud/instance/bootstrap-precheck-ok"
USER_DATA_TEMPLATE = ROOT / "templates" / "proxmox-user-data.yml.tmpl"
TEST_SSH_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIB4YrFhM2yPVzO+3kI14mYw3V91sCi1qdtB2bWjBv7E4 "
    "cloud-init-validation@example.invalid"
)
FULL_VALIDATION = False


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate YAML mapping keys instead of silently replacing them."""


def construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def load_yaml(content: str, source: str) -> object:
    try:
        return yaml.load(content, Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise SystemExit(f"{source}: invalid YAML: {error}") from error


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if result.returncode:
        print(f"FAILED: {' '.join(command)}", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def write_file_map(config: dict) -> dict[str, str]:
    return {
        entry["path"]: entry.get("content", "")
        for entry in config.get("write_files", [])
    }


def validate_shell(script: str, source: str, shell: str) -> None:
    print(f"{shell} syntax {source}")
    run([shell, "-n"], input_text=script)
    if FULL_VALIDATION:
        print(f"shellcheck {source}")
        run(["shellcheck", "--shell", shell, "-"], input_text=script)


def require_fragments(text: str, fragments: tuple[str, ...], source: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        raise SystemExit(f"{source}: required content is missing: {missing}")


def validate_systemd_unit(
    text: str,
    source: str,
    *,
    required: dict[str, set[str]],
) -> None:
    sections: dict[str, set[str]] = {}
    current_section: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r"\[([A-Za-z][A-Za-z0-9]*)\]", line)
        if section_match:
            current_section = section_match.group(1)
            sections.setdefault(current_section, set())
            continue
        if current_section is None or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*=.*", line):
            raise SystemExit(f"{source}: invalid systemd unit line {line_number}: {line}")
        sections[current_section].add(line)

    for section, expected_lines in required.items():
        missing = expected_lines - sections.get(section, set())
        if missing:
            raise SystemExit(
                f"{source}: systemd [{section}] is missing entries: {sorted(missing)}"
            )


def validate_proxmox_user_data() -> None:
    template = USER_DATA_TEMPLATE.read_text(encoding="utf-8")
    marker = "@@SSH_PUBLIC_KEY@@"
    if template.count(marker) != 1:
        raise SystemExit(
            f"{USER_DATA_TEMPLATE}: expected exactly one SSH public key marker"
        )
    if not template.startswith("#cloud-config\n"):
        raise SystemExit(f"{USER_DATA_TEMPLATE}: cloud-config header is missing")

    rendered = template.replace(marker, TEST_SSH_PUBLIC_KEY)
    config = load_yaml(rendered, str(USER_DATA_TEMPLATE))
    if not isinstance(config, dict) or "user" in config:
        raise SystemExit(
            f"{USER_DATA_TEMPLATE}: legacy scalar user configuration is forbidden"
        )

    expected_user = {
        "name": "admin",
        "gecos": "Admin",
        "groups": ["adm", "sudo"],
        "shell": "/bin/bash",
        "sudo": "ALL=(ALL) NOPASSWD:ALL",
        "lock_passwd": True,
        "ssh_authorized_keys": [TEST_SSH_PUBLIC_KEY],
    }
    if config.get("users") != [expected_user]:
        raise SystemExit(
            f"{USER_DATA_TEMPLATE}: admin user configuration is incomplete"
        )

    if FULL_VALIDATION:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml") as rendered_file:
            rendered_file.write(rendered)
            rendered_file.flush()
            print(f"cloud-init schema {USER_DATA_TEMPLATE.name}")
            run(["cloud-init", "schema", "--config-file", rendered_file.name])

    print("modern Proxmox user-data template validated")


def validate_common(
    config: dict,
    files: dict[str, str],
    profile_name: str,
) -> None:
    ssh_config = files["/etc/ssh/sshd_config.d/99-harden.conf"]
    require_fragments(
        ssh_config,
        (
            "PasswordAuthentication no",
            "PermitRootLogin no",
            "AuthenticationMethods publickey",
        ),
        profile_name,
    )

    fail2ban = files["/etc/fail2ban/jail.local"]
    expected_ignore = f'ignoreip = {SITE["FAIL2BAN_IGNORE_IPS"]}'
    if expected_ignore not in fail2ban:
        raise SystemExit(f"{profile_name}: fail2ban ignore list does not match .env")

    if "power_state" in config:
        raise SystemExit(
            f"{profile_name}: poweroff must be owned by the post-cloud-init verifier"
        )

    if config.get("runcmd") != [["/usr/local/sbin/cloud-init-finalize"]]:
        raise SystemExit(f"{profile_name}: final validation must be the only runcmd")
    if config.get("package_reboot_if_required") is not False:
        raise SystemExit(f"{profile_name}: package upgrades must not reboot bootstrap")
    if config.get("preserve_hostname") is not False:
        raise SystemExit(f"{profile_name}: cloud-init must update the hostname")
    if config.get("create_hostname_file") is not True:
        raise SystemExit(f"{profile_name}: cloud-init must create /etc/hostname")
    if config.get("manage_etc_hosts") is not True:
        raise SystemExit(f"{profile_name}: cloud-init must manage /etc/hosts")

    finalizer = files["/usr/local/sbin/cloud-init-finalize"]
    require_fragments(
        finalizer,
        (
            'rm -f "$success_marker" "$precheck_marker"',
            "sysctl --system",
            "systemctl is-active --quiet qemu-guest-agent.service",
            "systemctl is-active --quiet unattended-upgrades.service",
            "fail2ban-client -t",
            "/usr/sbin/sshd -t",
            "/usr/local/sbin/cloud-init-report failure",
            "cloud-init query v1.local_hostname",
            'hostnamectl --static 2>/dev/null || true',
            'if [ "$(hostname)" != "$cloud_hostname" ]',
            'if [ "$(cat /etc/hostname)" != "$cloud_hostname" ]',
            'touch "$precheck_marker"',
            "systemctl start --no-block cloud-init-post-verify.service",
        ),
        profile_name,
    )
    if "/usr/local/sbin/cloud-init-report success" in finalizer:
        raise SystemExit(f"{profile_name}: finalizer reports success before cloud-init ends")
    if 'touch "$success_marker"' in finalizer:
        raise SystemExit(f"{profile_name}: finalizer writes the success marker too early")
    if "hostnamectl set-hostname" in finalizer:
        raise SystemExit(
            f"{profile_name}: finalizer must validate, not change, the hostname"
        )

    post_verifier = files["/usr/local/sbin/cloud-init-post-verify"]
    require_fragments(
        post_verifier,
        (
            PRECHECK_MARKER,
            "/var/lib/cloud/instance/boot-finished",
            "cloud-init status --format json",
            'if [ "$cloud_status_exit" -ne 0 ]',
            "/usr/local/sbin/cloud-init-report success",
            'touch "$success_marker"',
            "/usr/sbin/shutdown --poweroff +1",
        ),
        profile_name,
    )
    success_report = post_verifier.rfind("/usr/local/sbin/cloud-init-report success")
    success_touch = post_verifier.rfind('touch "$success_marker"')
    shutdown = post_verifier.rfind("/usr/sbin/shutdown --poweroff +1")
    if not success_report < success_touch < shutdown:
        raise SystemExit(f"{profile_name}: post-cloud-init success ordering is unsafe")

    post_unit = files["/etc/systemd/system/cloud-init-post-verify.service"]
    validate_systemd_unit(
        post_unit,
        profile_name,
        required={
            "Unit": {
                "Wants=cloud-init.target",
                "After=cloud-init.target",
                f"ConditionPathExists={PRECHECK_MARKER}",
                f"ConditionPathExists=!{SUCCESS_MARKER}",
            },
            "Service": {
                "Type=oneshot",
                "ExecStart=/usr/local/sbin/cloud-init-post-verify",
                "RemainAfterExit=yes",
            },
        },
    )

    report = files["/usr/local/sbin/cloud-init-report"]
    require_fragments(
        report,
        (
            "dpkg-query --show",
            '"$log_dir/packages.tsv"',
        ),
        profile_name,
    )

    hardening = files["/etc/sysctl.d/20-hardening.conf"]
    require_fragments(
        hardening,
        (
            "kernel.kptr_restrict = 2",
            "net.ipv4.conf.all.rp_filter = 2",
            "net.ipv4.tcp_syncookies = 1",
        ),
        profile_name,
    )

    unattended = files["/etc/apt/apt.conf.d/52unattended-upgrades-local"]
    require_fragments(
        unattended,
        (
            "codename=${distro_codename}-security",
            'Unattended-Upgrade::Automatic-Reboot "false";',
        ),
        profile_name,
    )


def validate_docker(files: dict[str, str], profile_name: str) -> None:
    daemon_config = files["/etc/docker/daemon.json"]
    daemon_settings = json.loads(daemon_config)
    if daemon_settings.get("data-root") != "/mnt/appdata/docker":
        raise SystemExit(f"{profile_name}: Docker data-root is not on APPDATA")
    if FULL_VALIDATION:
        print(f"dockerd --validate {profile_name}")
        run(
            ["dockerd", "--validate", "--config-file", "/dev/stdin"],
            input_text=daemon_config,
        )

    key = files["/etc/apt/keyrings/docker.asc"]
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    if key_digest != DOCKER_KEY_SHA256:
        raise SystemExit(
            f"{profile_name}: unexpected Docker signing key digest {key_digest}"
        )
    if FULL_VALIDATION:
        with tempfile.TemporaryDirectory(prefix="cloud-init-gpg-") as homedir:
            os.chmod(homedir, 0o700)
            output = run(
                [
                    "gpg",
                    "--batch",
                    "--homedir",
                    homedir,
                    "--show-keys",
                    "--with-colons",
                ],
                input_text=key,
            )
        fingerprints = [
            line.split(":")[9]
            for line in output.splitlines()
            if line.startswith("fpr:")
        ]
        if not fingerprints or fingerprints[0] != DOCKER_KEY_FINGERPRINT:
            raise SystemExit(
                f"{profile_name}: unexpected Docker key fingerprint {fingerprints}"
            )

    expected_link = f'/dev/disk/by-id/wwn-{SITE["APPDATA_WWN"]}'
    appdata_verify = files["/usr/local/sbin/appdata-verify"]
    require_fragments(
        appdata_verify,
        (
            f"expected_link={expected_link}",
            f'[ "$expected_serial" = "{SITE["APPDATA_SERIAL"]}" ]',
            'findmnt -rn --mountpoint /mnt/appdata -o TARGET | wc -l',
            '[ "$app_mount_count" -eq 1 ]',
            'findmnt -rn --mountpoint /mnt/appdata -o SOURCE',
            'lsblk -dn -o MAJ:MIN -- "$expected_dev"',
            'lsblk -dn -o MAJ:MIN -- "$mounted_dev"',
            '"$mounted_id" != "$expected_id"',
            "APPDATA mount is not ext4",
            "APPDATA filesystem label is not APPDATA",
        ),
        profile_name,
    )

    appdata_unit = files["/etc/systemd/system/appdata-verify.service"]
    validate_systemd_unit(
        appdata_unit,
        profile_name,
        required={
            "Unit": {
                "RequiresMountsFor=/mnt/appdata",
                "Before=docker.service",
            },
            "Service": {
                "Type=oneshot",
                "ExecStart=/usr/local/sbin/appdata-verify",
                "RemainAfterExit=yes",
            },
        },
    )

    docker_dropin = files["/etc/systemd/system/docker.service.d/10-require-appdata.conf"]
    validate_systemd_unit(
        docker_dropin,
        profile_name,
        required={
            "Unit": {
                "RequiresMountsFor=/mnt/appdata",
                "Requires=appdata-verify.service",
                "After=appdata-verify.service",
            }
        },
    )

    report = files["/usr/local/sbin/cloud-init-report"]
    require_fragments(
        report,
        (
            "docker version",
            '"$log_dir/docker-version.txt"',
        ),
        profile_name,
    )


def validate_rsyslog(files: dict[str, str], profile_name: str) -> None:
    config = files["/etc/rsyslog.d/01-remote.conf"]
    require_fragments(
        config,
        (
            f'target="{SITE["SYSLOG_SERVER"]}"',
            f'port="{SITE["SYSLOG_PORT"]}"',
            'protocol="tcp"',
            'TCP_Framing="traditional"',
            'queue.filename="syslog-forward"',
            'queue.maxDiskSpace="256m"',
            "\nstop\n",
        ),
        profile_name,
    )
    forbidden_tls = (
        "DefaultNetstreamDriverCAFile",
        "StreamDriver",
        "x509/",
        "ossl",
        "gtls",
    )
    present_tls = [fragment for fragment in forbidden_tls if fragment in config]
    if present_tls:
        raise SystemExit(
            f"{profile_name}: plain TCP syslog contains TLS settings: {present_tls}"
        )
    if "logs.example.invalid" in config:
        raise SystemExit(f"{profile_name}: unresolved syslog placeholder remains")

    if FULL_VALIDATION:
        print(f"rsyslogd -N1 {profile_name}")
        run(
            ["/usr/sbin/rsyslogd", "-N1", "-f", "/dev/stdin"],
            input_text=config,
        )


def validate_readme() -> None:
    path = ROOT / "readme.md"
    content = path.read_text(encoding="utf-8")

    for stale_text in (
        "raw.githubusercontent.com",
        "archive/",
        "docker_graylog.yml",
        "ssh_authorized_keys:",
        "/home/logs",
        "SYSLOG_CA_FILE",
        "server-authenticated TLS",
        "receiver certificate",
        "rsyslog-openssl",
        "logs.example.invalid",
        "PROFILE_SHA256=",
        "site.env",
        "template-build.env",
    ):
        if stale_text in content:
            raise SystemExit(f"readme.md: stale instruction remains: {stale_text}")

    expected_headings = (
        "## What this repo does",
        "## What's inside the templates",
        "## Basic logic of the repo",
        "## Install Step #1: Create the cloud-init templates",
        "## Install Step #2: add template on Proxmox",
        "## To Do List",
        "## How is AI used in this repo?",
    )
    actual_headings = tuple(re.findall(r"(?m)^## .+$", content))
    if actual_headings != expected_headings:
        raise SystemExit(
            "readme.md: expected exactly these sections in order: "
            f"{list(expected_headings)}"
        )

    require_fragments(
        content,
        (
            ".env.example",
            "ARTIFACT_OUTPUT_DIR",
            "build_template_bundle.py",
            "create_proxmox_template.sh",
            "cp cloud-init/tools/.env.example cloud-init/tools/.env",
            "cloud-init/tools/validate.sh",
            "cloud-init/tools/create_proxmox_template.sh",
            'scp cloud-init/build/* "root@${PROXMOX_HOST}:${PROXMOX_SNIPPET_PATH}/"',
            "create-deb13-plain-template.sh",
            "TLS or RELP",
            "QEMU/Proxmox",
        ),
        "readme.md",
    )

    wrapper = ROOT / "tools" / "create_proxmox_template.sh"
    wrapper_script = wrapper.read_text(encoding="utf-8")
    run(["bash", "-n", str(wrapper)])
    validate_shell(wrapper_script, str(wrapper), "bash")
    require_fragments(
        wrapper_script,
        (
            "build_template_bundle.py",
            'exec python3 "$script_dir/build_template_bundle.py"',
        ),
        str(wrapper),
    )

    builder = ROOT / "tools" / "build_template_bundle.py"
    builder_script = builder.read_text(encoding="utf-8")
    require_fragments(
        builder_script,
        (
            '"ARTIFACT_OUTPUT_DIR"',
            "vendor_artifacts()",
            "render_command",
            "os.replace",
            'f"create-{vendor.template_name}.sh"',
            "proxmox-create-command.sh.tmpl",
        ),
        str(builder),
    )
    run([sys.executable, "-m", "py_compile", str(builder)])
    run([sys.executable, str(builder), "--validate"])

    command_template = (
        ROOT / "templates" / "proxmox-create-command.sh.tmpl"
    ).read_text(encoding="utf-8")
    require_fragments(
        command_template,
        (
            'qm destroy "$current_vmid" --purge 1',
            '--cicustom "vendor=${SNIPPET_STORAGE_NAME}:snippets/',
            "VENDOR_SNIPPET_NAME=@@VENDOR_SNIPPET_NAME@@",
            "VMID=@@VMID@@",
            'create_template "$VMID" "$NAME"',
            "@@IMAGE_SHA512@@",
        ),
        "proxmox-create-command.sh.tmpl",
    )
    if "qm resize" in command_template:
        raise SystemExit("template creation script must not resize the root disk")
    for legacy_option in ("--ciuser", "--sshkeys"):
        if legacy_option in command_template:
            raise SystemExit(
                f"template creation script retains legacy Proxmox option {legacy_option}"
            )
    if not re.search(r'IMAGE_SHA512 = \(\n(?:\s+"[0-9a-f]+"\n)+\)', builder_script):
        raise SystemExit("template creation script is missing the Debian image pin")

    example_config = ROOT / "tools" / ".env.example"
    if not example_config.is_file() or ".env\n" not in (ROOT / ".gitignore").read_text(
        encoding="utf-8"
    ):
        raise SystemExit("single local .env workflow is not configured")
    example_content = example_config.read_text(encoding="utf-8")
    require_fragments(
        example_content,
        ("VMID_START=", "NAME_PREFIX=", "SSH_PUBLIC_KEY_FILE="),
        str(example_config),
    )
    if re.search(r"(?m)^PROFILE=", example_content):
        raise SystemExit(f"{example_config}: PROFILE must not select one template")

    print("readme.md and local artifact bundle workflow validated")


def require_full_validation_tools() -> None:
    commands = ("cloud-init", "dockerd", "gpg", "shellcheck", "yamllint")
    missing = [command for command in commands if shutil.which(command) is None]
    if not Path("/usr/sbin/rsyslogd").is_file():
        missing.append("rsyslogd")
    if missing:
        raise SystemExit(
            "full validation requires these missing commands: " + ", ".join(missing)
        )


def main() -> int:
    global FULL_VALIDATION
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run validators supplied by cloud-init, Docker, GnuPG, rsyslog, and lint tools",
    )
    arguments = parser.parse_args()
    FULL_VALIDATION = arguments.full
    if FULL_VALIDATION:
        require_full_validation_tools()

    ssh_baseline: str | None = None

    validate_proxmox_user_data()

    for profile in PROFILES:
        rendered = render(profile)
        if FULL_VALIDATION:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yml") as rendered_file:
                rendered_file.write(rendered)
                rendered_file.flush()
                print(f"cloud-init schema {profile.output}")
                run(["cloud-init", "schema", "--config-file", rendered_file.name])
                run(
                    [
                        "yamllint",
                        "-c",
                        str(ROOT / ".yamllint.yml"),
                        rendered_file.name,
                    ]
                )

        config = load_yaml(rendered, profile.output)
        files = write_file_map(config)
        validate_common(config, files, profile.output)
        if "users" in config or "user" in config:
            raise SystemExit(
                f"{profile.output}: user identity must be owned by custom user data"
            )

        packages = config.get("packages", [])
        if not all(isinstance(package, str) and "=" not in package for package in packages):
            raise SystemExit(f"{profile.output}: package versions must remain unpinned")
        if any(path.startswith("/etc/apt/preferences") for path in files):
            raise SystemExit(f"{profile.output}: APT package pins are not allowed")
        if config.get("growpart") != {"mode": "auto"}:
            raise SystemExit(f"{profile.output}: root partition growth configuration drifted")
        if config.get("resize_rootfs") is not True:
            raise SystemExit(f"{profile.output}: root filesystem growth must remain enabled")

        ssh_config = files["/etc/ssh/sshd_config.d/99-harden.conf"]
        if ssh_baseline is None:
            ssh_baseline = ssh_config
        elif ssh_config != ssh_baseline:
            raise SystemExit(f"{profile.output}: SSH baseline drifted")

        if "ssh_authorized_keys" in rendered:
            raise SystemExit(f"{profile.output}: committed SSH key material is forbidden")

        for index, command in enumerate(config.get("bootcmd", [])):
            if isinstance(command, str) and "\n" in command:
                validate_shell(
                    f"#!/bin/sh\n{command}",
                    f"{profile.output}:bootcmd[{index}]",
                    "sh",
                )

        for script_path in (
            "/usr/local/sbin/cloud-init-report",
            "/usr/local/sbin/cloud-init-post-verify",
            "/usr/local/sbin/cloud-init-finalize",
        ):
            validate_shell(files[script_path], f"{profile.output}:{script_path}", "bash")

        if profile.docker:
            validate_docker(files, profile.output)
            if "mounts" not in config or "bootcmd" not in config:
                raise SystemExit(f"{profile.output}: APPDATA provisioning is missing")
            expected_link = f'/dev/disk/by-id/wwn-{SITE["APPDATA_WWN"]}'
            expected_mount = [
                expected_link,
                "/mnt/appdata",
                "ext4",
                (
                    "defaults,noatime,x-systemd.growfs,nodev,"
                    "x-systemd.device-timeout=30s"
                ),
                "0",
                "2",
            ]
            if config["mounts"] != [expected_mount]:
                raise SystemExit(
                    f"{profile.output}: cloud-init must own exactly one APPDATA mount"
                )
            boot_script = "\n".join(
                command
                for command in config["bootcmd"]
                if isinstance(command, str)
            )
            if expected_link not in boot_script:
                raise SystemExit(f"{profile.output}: deterministic APPDATA ID is missing")
            if "scsi-3" in boot_script or "head -n1" in boot_script:
                raise SystemExit(f"{profile.output}: broad disk discovery is forbidden")
            if (
                "app_signatures" not in boot_script
                or "app_children" not in boot_script
                or "wipefs -n --noheadings --output TYPE" not in boot_script
            ):
                raise SystemExit(f"{profile.output}: destructive disk guards are missing")
            if f'app_serial" = "{SITE["APPDATA_SERIAL"]}"' not in boot_script:
                raise SystemExit(f"{profile.output}: APPDATA serial guard is missing")
            if "appdata-provisioned" in boot_script:
                raise SystemExit(
                    f"{profile.output}: APPDATA identity checks must run on every boot"
                )
            if re.search(
                r"(?m)^\s*(?:/usr/bin/|/bin/)?mount(?:\s|$)",
                boot_script,
            ):
                raise SystemExit(
                    f"{profile.output}: bootcmd must not mount APPDATA; use mounts"
                )
            mount_options = config["mounts"][0][3]
            if "nofail" in mount_options or "x-systemd.device-timeout=30s" not in mount_options:
                raise SystemExit(f"{profile.output}: APPDATA mount is not fail-closed")
            appdata_verify = files["/usr/local/sbin/appdata-verify"]
            validate_shell(
                appdata_verify,
                f"{profile.output}:/usr/local/sbin/appdata-verify",
                "bash",
            )
            finalizer = files["/usr/local/sbin/cloud-init-finalize"]
            require_fragments(
                finalizer,
                (
                    "systemctl start appdata-verify.service",
                    "systemctl is-active --quiet appdata-verify.service",
                ),
                profile.output,
            )
        else:
            if "mounts" in config or "bootcmd" in config:
                raise SystemExit(f"{profile.output}: plain profiles must not format APPDATA")
            if any("appdata" in path.lower() for path in files):
                raise SystemExit(f"{profile.output}: plain profile contains APPDATA files")

        if profile.syslog:
            validate_rsyslog(files, profile.output)
            if "rsyslog-openssl" in config.get("packages", []):
                raise SystemExit(
                    f"{profile.output}: plain TCP syslog must not install TLS support"
                )
            finalizer = files["/usr/local/sbin/cloud-init-finalize"]
            require_fragments(
                finalizer,
                (
                    "install -d -m 0700 -o root -g root /var/spool/rsyslog",
                    "/usr/sbin/rsyslogd -N1",
                ),
                profile.output,
            )
            if "update-ca-certificates" in finalizer:
                raise SystemExit(
                    f"{profile.output}: plain TCP finalizer contains TLS setup"
                )
        elif any(path.startswith("/etc/rsyslog") for path in files):
            raise SystemExit(f"{profile.output}: unexpected rsyslog configuration")

    validate_readme()
    print("All cloud-init profiles validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
