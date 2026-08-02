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
PROXMOX_SCALAR_USER_WARNING = (
    "'user' of type string is deprecated in 22.2 and scheduled "
    "to be removed in 27.2. Use 'users' list instead."
)
FULL_VALIDATION = False
# Written once by the first-boot bootstrap sequence, then the template powers
# off. The only on-disk log destination the syslog profiles are allowed to keep.
BOOTSTRAP_REPORT_DIR = "/home/admin/logs"
RAM_LOGGING_PATHS = (
    "/etc/systemd/system/var-log.mount",
    "/etc/systemd/system/rsyslog.service.d/10-runtime-dir.conf",
    "/etc/tmpfiles.d/60-ram-logging.conf",
    "/etc/fail2ban/fail2ban.local",
)


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


def validate_post_verifier_behavior(post_verifier: str, source: str) -> None:
    clean_status = {
        "status": "done",
        "extended_status": "done",
        "errors": [],
        "recoverable_errors": {},
    }
    approved_degraded_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": [],
        "recoverable_errors": {
            "DEPRECATED": [
                PROXMOX_SCALAR_USER_WARNING,
                PROXMOX_SCALAR_USER_WARNING,
            ]
        },
    }
    approved_single_deprecation_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": [],
        "recoverable_errors": {
            "DEPRECATED": [PROXMOX_SCALAR_USER_WARNING]
        },
    }
    empty_deprecation_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": [],
        "recoverable_errors": {"DEPRECATED": []},
    }
    hard_error_status = {
        "status": "error",
        "extended_status": "error - done",
        "errors": ["cloud-init failed"],
        "recoverable_errors": {},
    }
    unexpected_warning_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": [],
        "recoverable_errors": {
            "DEPRECATED": [PROXMOX_SCALAR_USER_WARNING],
            "WARNING": ["unexpected recoverable warning"],
        },
    }
    unexpected_deprecation_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": [],
        "recoverable_errors": {
            "DEPRECATED": ["unexpected deprecation warning"]
        },
    }
    degraded_hard_error_status = {
        "status": "done",
        "extended_status": "degraded done",
        "errors": ["unexpected hard error"],
        "recoverable_errors": {
            "DEPRECATED": [PROXMOX_SCALAR_USER_WARNING]
        },
    }
    scenarios = (
        ("clean", 0, json.dumps(clean_status), True),
        (
            "approved-degraded",
            2,
            json.dumps(approved_degraded_status),
            True,
        ),
        (
            "approved-single-deprecation",
            2,
            json.dumps(approved_single_deprecation_status),
            True,
        ),
        ("hard-exit", 1, json.dumps(hard_error_status), False),
        ("unknown-exit", 3, json.dumps(clean_status), False),
        ("malformed-json", 2, "{not-json", False),
        (
            "empty-deprecation",
            2,
            json.dumps(empty_deprecation_status),
            False,
        ),
        (
            "unexpected-warning",
            2,
            json.dumps(unexpected_warning_status),
            False,
        ),
        (
            "unexpected-deprecation",
            2,
            json.dumps(unexpected_deprecation_status),
            False,
        ),
        (
            "degraded-hard-error",
            2,
            json.dumps(degraded_hard_error_status),
            False,
        ),
    )

    print(f"post-verifier behavior {source}")
    with tempfile.TemporaryDirectory(
        prefix="cloud-init-post-verify-check."
    ) as temp_dir:
        root = Path(temp_dir)
        for name, cloud_status_exit, cloud_status_output, approved in scenarios:
            scenario_dir = root / name
            scenario_dir.mkdir()
            success_marker = scenario_dir / "boot-success"
            precheck_marker = scenario_dir / "bootstrap-precheck-ok"
            boot_finished = scenario_dir / "boot-finished"
            status_fixture = scenario_dir / "status.json"
            report_log = scenario_dir / "report.log"
            shutdown_log = scenario_dir / "shutdown.log"
            cloud_init_stub = scenario_dir / "cloud-init"
            report_stub = scenario_dir / "cloud-init-report"
            shutdown_stub = scenario_dir / "shutdown"
            test_script_path = scenario_dir / "cloud-init-post-verify"

            precheck_marker.touch()
            boot_finished.touch()
            status_fixture.write_text(
                cloud_status_output + "\n",
                encoding="utf-8",
            )
            cloud_init_stub.write_text(
                "#!/bin/sh\n"
                'cat "$CLOUD_STATUS_FIXTURE"\n'
                'exit "$CLOUD_STATUS_EXIT"\n',
                encoding="utf-8",
            )
            report_stub.write_text(
                "#!/bin/sh\n"
                'printf \'%s\\n\' "$*" >> "$REPORT_LOG"\n',
                encoding="utf-8",
            )
            shutdown_stub.write_text(
                "#!/bin/sh\n"
                'printf \'%s\\n\' "$*" >> "$SHUTDOWN_LOG"\n',
                encoding="utf-8",
            )

            test_script = post_verifier
            replacements = {
                SUCCESS_MARKER: str(success_marker),
                PRECHECK_MARKER: str(precheck_marker),
                "/var/lib/cloud/instance/boot-finished": str(boot_finished),
                "cloud-init status --format json": (
                    f"bash {cloud_init_stub} status --format json"
                ),
                "/usr/local/sbin/cloud-init-report": f"bash {report_stub}",
                "/usr/sbin/shutdown": f"bash {shutdown_stub}",
            }
            for old, new in replacements.items():
                if old not in test_script:
                    raise SystemExit(
                        f"{source}: test harness could not replace {old}"
                    )
                test_script = test_script.replace(old, new)
            test_script_path.write_text(test_script, encoding="utf-8")

            environment = os.environ.copy()
            environment.update(
                {
                    "CLOUD_STATUS_FIXTURE": str(status_fixture),
                    "CLOUD_STATUS_EXIT": str(cloud_status_exit),
                    "REPORT_LOG": str(report_log),
                    "SHUTDOWN_LOG": str(shutdown_log),
                }
            )
            result = subprocess.run(
                ["bash", str(test_script_path)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            expected_exit = 0 if approved else cloud_status_exit
            if result.returncode != expected_exit:
                raise SystemExit(
                    f"{source}: {name} returned {result.returncode}, "
                    f"expected {expected_exit}\nstdout:\n{result.stdout}"
                    f"stderr:\n{result.stderr}"
                )
            if cloud_status_output not in result.stdout:
                raise SystemExit(
                    f"{source}: {name} did not print captured status output"
                )

            report_lines = (
                report_log.read_text(encoding="utf-8").splitlines()
                if report_log.exists()
                else []
            )
            shutdown_called = shutdown_log.exists()
            if approved:
                if not success_marker.is_file():
                    raise SystemExit(
                        f"{source}: {name} did not create the success marker"
                    )
                if report_lines != ["success 0 0"]:
                    raise SystemExit(
                        f"{source}: {name} emitted unexpected reports: "
                        f"{report_lines}"
                    )
                if not shutdown_called:
                    raise SystemExit(
                        f"{source}: {name} did not request shutdown"
                    )
            else:
                if success_marker.exists():
                    raise SystemExit(
                        f"{source}: {name} created the success marker"
                    )
                if len(report_lines) != 1 or not re.fullmatch(
                    rf"failure {cloud_status_exit} [0-9]+",
                    report_lines[0],
                ):
                    raise SystemExit(
                        f"{source}: {name} emitted unexpected reports: "
                        f"{report_lines}"
                    )
                if shutdown_called:
                    raise SystemExit(
                        f"{source}: {name} requested shutdown after failure"
                    )


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
    if "users" in config or "user" in config:
        raise SystemExit(
            f"{profile_name}: user identity must be owned by "
            "Proxmox-generated user-data"
        )

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
            'static_hostname="$(hostnamectl --static 2>/dev/null || true)"',
            'runtime_hostname="$(hostname 2>/dev/null || true)"',
            'if [ "$runtime_hostname" != "$static_hostname" ]',
            'if [ "$file_hostname" != "$static_hostname" ]',
            "getent passwd admin >/dev/null",
            "passwd --lock admin",
            "visudo -cf /etc/sudoers.d/90-admin",
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
            'if cloud_status_output="$(cloud-init status --format json 2>&1)"; then',
            'case "$cloud_status_exit" in',
            "status.get(\"status\") == \"done\"",
            "status.get(\"extended_status\") == \"degraded done\"",
            "status.get(\"errors\") == []",
            'set(recoverable) == {"DEPRECATED"}',
            "all(message == expected for message in deprecated)",
            PROXMOX_SCALAR_USER_WARNING,
            "/usr/local/sbin/cloud-init-report success",
            'touch "$success_marker"',
            "/usr/sbin/shutdown --poweroff +1",
        ),
        profile_name,
    )
    if "set +e" in post_verifier:
        raise SystemExit(
            f"{profile_name}: post-verifier must not disable errexit"
        )
    if 'if [ "$cloud_status_exit" -ne 0 ]' in post_verifier:
        raise SystemExit(
            f"{profile_name}: post-verifier retains the legacy status policy"
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
            'StateFile="/run/rsyslog/imjournal.state"',
            'Ratelimit.Interval="60"',
            'Ratelimit.Burst="25000"',
            'queue.saveOnShutdown="off"',
            'queue.timeoutEnqueue="0"',
            "\nstop\n",
        ),
        profile_name,
    )
    # Scan directives only. Comments explain what is deliberately absent, so
    # matching them would flag the explanation instead of a real setting.
    directives = "\n".join(
        line
        for line in config.splitlines()
        if not line.lstrip().startswith("#")
    )
    # Naming a queue file is what makes the queue disk-assisted, and overriding
    # workDirectory from an included file reaches the whole daemon.
    forbidden_disk = (
        "queue.filename",
        "queue.maxDiskSpace",
        "workDirectory",
        "/var/spool/",
    )
    present_disk = [fragment for fragment in forbidden_disk if fragment in directives]
    if present_disk:
        raise SystemExit(
            f"{profile_name}: syslog forwarding spools to disk: {present_disk}"
        )
    forbidden_tls = (
        "DefaultNetstreamDriverCAFile",
        "StreamDriver",
        "x509/",
        "ossl",
        "gtls",
    )
    present_tls = [fragment for fragment in forbidden_tls if fragment in directives]
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


def validate_ram_logging(files: dict[str, str], profile_name: str) -> None:
    """Syslog profiles keep every log in RAM; the collector is the durable copy."""
    validate_systemd_unit(
        files["/etc/systemd/system/var-log.mount"],
        f"{profile_name}:var-log.mount",
        required={
            "Mount": {
                "What=tmpfs",
                "Where=/var/log",
                "Type=tmpfs",
                "Options=mode=0755,nosuid,nodev,noexec,size=128M",
            },
            "Install": {"WantedBy=local-fs.target"},
        },
    )
    # rsyslog is socket-activated, so systemd-tmpfiles ordering cannot be relied
    # on to have created /run/rsyslog before imjournal opens its state file.
    validate_systemd_unit(
        files["/etc/systemd/system/rsyslog.service.d/10-runtime-dir.conf"],
        f"{profile_name}:rsyslog runtime directory",
        required={
            "Service": {
                "RuntimeDirectory=rsyslog",
                "RuntimeDirectoryPreserve=yes",
            }
        },
    )

    journald = files["/etc/systemd/journald.conf.d/60-remote-syslog.conf"]
    require_fragments(
        journald,
        ("Storage=volatile", "RuntimeMaxUse=64M"),
        f"{profile_name}:journald",
    )

    fail2ban = files["/etc/fail2ban/fail2ban.local"]
    require_fragments(fail2ban, ("logtarget = SYSTEMD-JOURNAL",), profile_name)
    for line in fail2ban.splitlines():
        if line.startswith("dbfile") and not line.split("=", 1)[1].strip().startswith(
            "/run/"
        ):
            raise SystemExit(f"{profile_name}: fail2ban ban database is not in /run")

    # Paths under /var/log are on the tmpfs, so they are RAM. What is still disk
    # is /var/spool, and /var/log/journal would make the journal persistent again
    # by giving Storage= somewhere to land if it ever drifts off volatile.
    for path, content in files.items():
        if path.startswith("/var/spool/"):
            raise SystemExit(f"{profile_name}: {path} writes to the disk spool")
        directives = "\n".join(
            line
            for line in content.splitlines()
            if not line.lstrip().startswith("#")
        )
        for disk_path in re.findall(r"/var/(?:spool|log/journal)[A-Za-z0-9_./-]*", directives):
            raise SystemExit(
                f"{profile_name}: {path} names an on-disk log destination {disk_path}"
            )

    # The first-boot bootstrap report is the one sanctioned on-disk destination.
    # Widening this allowance is what would quietly undo RAM-only logging, so it
    # is named here rather than left implicit.
    report = files["/usr/local/sbin/cloud-init-report"]
    if BOOTSTRAP_REPORT_DIR not in report:
        raise SystemExit(
            f"{profile_name}: bootstrap report no longer writes {BOOTSTRAP_REPORT_DIR}"
        )


def validate_template_wrapper() -> None:
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


def validate_bundle_builder() -> None:
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
            "prepare_output_directory",
            "BUNDLE_MARKER",
        ),
        str(builder),
    )
    run([sys.executable, "-m", "py_compile", str(builder)])
    run([sys.executable, str(builder), "--validate"])

    if not re.search(r'IMAGE_SHA512 = \(\n(?:\s+"[0-9a-f]+"\n)+\)', builder_script):
        raise SystemExit(f"{builder}: missing the Debian image pin")


def validate_artifact_writer_boundary() -> None:
    # The bundle builder is the only artifact writer. Two writers meant two
    # output-path behaviours, one of which ignored ARTIFACT_OUTPUT_DIR.
    renderer = ROOT / "tools" / "render_profiles.py"
    renderer_script = renderer.read_text(encoding="utf-8")
    for writing_call in ("write_text(", "write_bytes(", "mkdir(", "os.replace"):
        if writing_call in renderer_script:
            raise SystemExit(
                f"render_profiles.py must not write files, found {writing_call}; "
                "build_template_bundle.py is the only artifact writer"
            )


def validate_creation_template() -> None:
    command_template = (
        ROOT / "templates" / "proxmox-create-command.sh.tmpl"
    ).read_text(encoding="utf-8")
    require_fragments(
        command_template,
        (
            'qm destroy "$current_vmid" --purge 1',
            # One resolved volume string feeds both the checksum and qm create,
            # so the file that is verified is the file cloud-init reads.
            'vendor_volume="${SNIPPET_STORAGE_NAME}:snippets/${VENDOR_SNIPPET_NAME}"',
            'pvesm status --storage "$SNIPPET_STORAGE_NAME"',
            'vendor_path="$(pvesm path "$vendor_volume")"',
            '--cicustom "vendor=${vendor_volume}"',
            "VENDOR_SNIPPET_NAME=@@VENDOR_SNIPPET_NAME@@",
            "VMID=@@VMID@@",
            'create_template "$VMID" "$NAME"',
            "@@IMAGE_SHA512@@",
        ),
        "proxmox-create-command.sh.tmpl",
    )
    if 'qm resize "$vmid" scsi0 "${ROOT_DISK_SIZE}G"' not in command_template:
        raise SystemExit("template creation script must resize the root disk to ROOT_DISK_SIZE")

    # Proxmox only emits the hostname in the user-data it generates itself, so
    # the identity options are required and a custom user= snippet is forbidden.
    require_fragments(
        command_template,
        (
            "--ciuser admin",
            '--sshkeys "$ssh_key_file"',
            "--ciupgrade 0",
            "SSH_PUBLIC_KEY=@@SSH_PUBLIC_KEY@@",
            'qm cloudinit dump "$vmid" user',
        ),
        "proxmox-create-command.sh.tmpl",
    )

    cicustom_lines = [
        line
        for line in command_template.splitlines()
        if "--cicustom" in line
    ]

    if len(cicustom_lines) != 1:
        raise SystemExit(
            "creation script must contain exactly one --cicustom option"
        )

    if "user=" in cicustom_lines[0]:
        raise SystemExit(
            "creation script must use Proxmox-generated user-data"
        )


def validate_local_env_workflow() -> None:
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
    post_verifier_baseline: str | None = None

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
        post_verifier = files["/usr/local/sbin/cloud-init-post-verify"]
        if post_verifier_baseline is None:
            validate_post_verifier_behavior(post_verifier, profile.output)
            post_verifier_baseline = post_verifier
        elif post_verifier != post_verifier_baseline:
            raise SystemExit(
                f"{profile.output}: post-verifier behavior differs by profile"
            )
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
            validate_ram_logging(files, profile.output)
            if "rsyslog-openssl" in config.get("packages", []):
                raise SystemExit(
                    f"{profile.output}: plain TCP syslog must not install TLS support"
                )
            finalizer = files["/usr/local/sbin/cloud-init-finalize"]
            require_fragments(
                finalizer,
                (
                    "systemctl enable var-log.mount",
                    "systemctl is-enabled --quiet var-log.mount",
                    "[ -e /run/rsyslog/imjournal.state ]",
                    "/usr/sbin/rsyslogd -N1",
                ),
                profile.output,
            )
            if "/var/spool/rsyslog" in finalizer:
                raise SystemExit(
                    f"{profile.output}: finalizer still provisions the disk spool"
                )
            # Starting the mount mid-build would shadow the /var/log that
            # cloud-init is still writing into and that the report script reads.
            if "systemctl start var-log.mount" in finalizer or (
                "systemctl enable --now var-log.mount" in finalizer
            ):
                raise SystemExit(
                    f"{profile.output}: var-log.mount must be enabled, not started"
                )
            if "update-ca-certificates" in finalizer:
                raise SystemExit(
                    f"{profile.output}: plain TCP finalizer contains TLS setup"
                )
        else:
            if any(path.startswith("/etc/rsyslog") for path in files):
                raise SystemExit(f"{profile.output}: unexpected rsyslog configuration")
            for ram_only_path in RAM_LOGGING_PATHS:
                if ram_only_path in files:
                    raise SystemExit(
                        f"{profile.output}: RAM-only logging is scoped to the "
                        f"syslog profiles, but {ram_only_path} is present"
                    )

    validate_template_wrapper()
    validate_bundle_builder()
    validate_artifact_writer_boundary()
    validate_creation_template()
    validate_local_env_workflow()
    print("local artifact bundle workflow validated")
    print("All cloud-init profiles validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
