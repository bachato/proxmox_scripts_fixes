#!/usr/bin/env python3
"""Validate generated cloud-init profiles and their embedded configurations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml

from render_profiles import PROFILES, ROOT


DOCKER_KEY_FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
SUCCESS_MARKER = "/var/lib/cloud/instance/boot-success"


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
    print(f"shellcheck {source}")
    run(["shellcheck", "--shell", shell, "-"], input_text=script)


def require_fragments(text: str, fragments: tuple[str, ...], source: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        raise SystemExit(f"{source}: required content is missing: {missing}")


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

    power_state = config.get("power_state", {})
    if power_state.get("mode") != "poweroff" or power_state.get("delay") != 1:
        raise SystemExit(f"{profile_name}: poweroff configuration is not deterministic")
    if power_state.get("condition") != ["test", "-f", SUCCESS_MARKER]:
        raise SystemExit(f"{profile_name}: poweroff is not gated by bootstrap success")

    if config.get("runcmd") != [["/usr/local/sbin/cloud-init-finalize"]]:
        raise SystemExit(f"{profile_name}: final validation must be the only runcmd")
    if config.get("package_reboot_if_required") is not False:
        raise SystemExit(f"{profile_name}: package upgrades must not reboot bootstrap")

    finalizer = files["/usr/local/sbin/cloud-init-finalize"]
    require_fragments(
        finalizer,
        (
            'rm -f "$success_marker"',
            "sysctl --system",
            "systemctl is-active --quiet qemu-guest-agent.service",
            "systemctl is-active --quiet unattended-upgrades.service",
            "fail2ban-client -t",
            "/usr/sbin/sshd -t",
            "/usr/local/sbin/cloud-init-report failure",
            "/usr/local/sbin/cloud-init-report success",
            'touch "$success_marker"',
        ),
        profile_name,
    )
    success_report = finalizer.rfind("/usr/local/sbin/cloud-init-report success")
    success_touch = finalizer.rfind('touch "$success_marker"')
    if success_report >= success_touch:
        raise SystemExit(f"{profile_name}: success marker is written too early")

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
    print(f"dockerd --validate {profile_name}")
    run(
        ["dockerd", "--validate", "--config-file", "/dev/stdin"],
        input_text=daemon_config,
    )

    key = files["/etc/apt/keyrings/docker.asc"]
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
        line.split(":")[9] for line in output.splitlines() if line.startswith("fpr:")
    ]
    if not fingerprints or fingerprints[0] != DOCKER_KEY_FINGERPRINT:
        raise SystemExit(
            f"{profile_name}: unexpected Docker key fingerprint {fingerprints}"
        )


def validate_rsyslog(files: dict[str, str], profile_name: str) -> None:
    config = files["/etc/rsyslog.d/01-remote.conf"]
    require_fragments(
        config,
        (
            'target="logs.example.invalid"',
            'port="5140"',
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
        "docker_graylog.yml",
        "ssh_authorized_keys:",
        "/home/logs",
        "SYSLOG_CA_FILE",
        "server-authenticated TLS",
        "receiver certificate",
        "rsyslog-openssl",
    ):
        if stale_text in content:
            raise SystemExit(f"readme.md: stale instruction remains: {stale_text}")

    reference_match = re.search(
        r"^CLOUD_INIT_REF=([0-9a-f]{40})$",
        content,
        flags=re.MULTILINE,
    )
    if not reference_match:
        raise SystemExit("readme.md: immutable CLOUD_INIT_REF is missing")
    reference = reference_match.group(1)

    repository = ROOT.parent
    run(["git", "-C", str(repository), "cat-file", "-e", f"{reference}^{{commit}}"])

    for profile in PROFILES:
        hash_match = re.search(
            rf"^\s*{re.escape(profile.output)}\)\s*$"
            rf"\s*PROFILE_SHA256=([0-9a-f]{{64}})$",
            content,
            flags=re.MULTILINE,
        )
        if not hash_match:
            raise SystemExit(f"readme.md: SHA-256 pin is missing for {profile.output}")

        expected_hash = hash_match.group(1)
        current_hash = hashlib.sha256((ROOT / profile.output).read_bytes()).hexdigest()
        if current_hash != expected_hash:
            raise SystemExit(f"readme.md: current {profile.output} does not match its pin")

        pinned_profile = run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{reference}:cloud-init/{profile.output}",
            ]
        )
        pinned_hash = hashlib.sha256(pinned_profile.encode("utf-8")).hexdigest()
        if pinned_hash != expected_hash:
            raise SystemExit(
                f"readme.md: {profile.output} does not match CLOUD_INIT_REF"
            )

    image_hash = re.search(
        r"^IMAGE_SHA512=([0-9a-f]{128})$",
        content,
        flags=re.MULTILINE,
    )
    if not image_hash:
        raise SystemExit("readme.md: Debian image SHA-512 pin is missing")

    bash_blocks = re.findall(r"```bash\n(.*?)\n```", content, flags=re.DOTALL)
    if not bash_blocks:
        raise SystemExit("readme.md: provisioning shell block is missing")
    run(["bash", "-n"], input_text=bash_blocks[0])
    validate_shell(bash_blocks[0], "readme.md:provisioning", "bash")
    print("readme.md immutable inputs and provisioning shell validated")


def main() -> int:
    ssh_baseline: str | None = None

    for profile in PROFILES:
        path = ROOT / profile.output
        print(f"cloud-init schema {profile.output}")
        run(["cloud-init", "schema", "--config-file", str(path)])
        run(["yamllint", "-c", str(ROOT / ".yamllint.yml"), str(path)])

        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        files = write_file_map(config)
        validate_common(config, files, profile.output)

        ssh_config = files["/etc/ssh/sshd_config.d/99-harden.conf"]
        if ssh_baseline is None:
            ssh_baseline = ssh_config
        elif ssh_config != ssh_baseline:
            raise SystemExit(f"{profile.output}: SSH baseline drifted")

        if "ssh_authorized_keys" in path.read_text(encoding="utf-8"):
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
            "/usr/local/sbin/cloud-init-finalize",
        ):
            validate_shell(files[script_path], f"{profile.output}:{script_path}", "bash")

        if profile.docker:
            validate_docker(files, profile.output)
            if "mounts" not in config or "bootcmd" not in config:
                raise SystemExit(f"{profile.output}: APPDATA provisioning is missing")
            expected_mount = [
                "LABEL=APPDATA",
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
            if "/dev/disk/by-id/wwn-0x2000000000000001" not in boot_script:
                raise SystemExit(f"{profile.output}: deterministic APPDATA ID is missing")
            if "scsi-3" in boot_script or "head -n1" in boot_script:
                raise SystemExit(f"{profile.output}: broad disk discovery is forbidden")
            if (
                "app_signatures" not in boot_script
                or "app_children" not in boot_script
                or "wipefs -n --noheadings --output TYPE" not in boot_script
            ):
                raise SystemExit(f"{profile.output}: destructive disk guards are missing")
            if 'app_serial" = APPDATA' not in boot_script:
                raise SystemExit(f"{profile.output}: APPDATA serial guard is missing")
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
            finalizer = files["/usr/local/sbin/cloud-init-finalize"]
            require_fragments(
                finalizer,
                (
                    'findmnt -rn --mountpoint /mnt/appdata -o TARGET | wc -l',
                    '[ "$app_mount_count" -eq 1 ]',
                    "APPDATA must be mounted exactly once",
                ),
                profile.output,
            )
        elif "mounts" in config or "bootcmd" in config:
            raise SystemExit(f"{profile.output}: plain profiles must not format APPDATA")

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
                    'grep -q "logs.example.invalid"',
                    "/etc/rsyslog.d/01-remote.conf",
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
