# Debian 13 cloud-init templates for Proxmox

## NOTE: This is the last update to this repo for cloud-init.  This project will from now on be maintained here:
https://github.com/kasa-consulting/kasa-cloud-init-public

## What this repo does

This is my workflow for building VM's using cloud-init, fully configured and ready to go in 2 mintues!

The files in this directory help you build four hardened Debian 13 templates for Proxmox. Each
template creates an `admin` user with your SSH key, disables password and root
SSH login, and installs security updates and the QEMU guest agent.

| Template | Docker | Remote syslog | APPDATA disk |
| --- | --- | --- | --- |
| Plain | No | No | No |
| Plain + syslog | No | Plain TCP | No |
| Docker | Yes | No | Yes |
| Docker + syslog | Yes | Plain TCP | Yes |

Docker variants add a dedicated APPDATA disk.
Syslog variants send logs over unencrypted TCP, so use them only on a trusted or separately protected network.  (TLS in the future)

Syslog variants also keep logging entirely in RAM: `/var/log` is a tmpfs, the
journal is volatile, and the forwarding queue is memory-only. Your collector is
the only durable copy. See "RAM-only logging" below for the tradeoffs.

## What's inside the templates

### Packages

Every template installs `ca-certificates`, `cloud-guest-utils`, `fail2ban`,
`nftables`, `openssh-server`, `qemu-guest-agent`, `sudo`,
`systemd-zram-generator`, `tmux`, and `unattended-upgrades`.

- Docker variants add `docker-ce`, `docker-ce-cli`, `containerd.io`,
  `docker-buildx-plugin`, and `docker-compose-plugin` from
  `download.docker.com`, signed by the pinned key in `assets/docker-release.asc`.
- Syslog variants add `rsyslog`.

First boot also runs a full package update and upgrade before anything else is
configured.

### Important config (Defaults and .env should be all you need)

| Area | What is set | Where |
| --- | --- | --- |
| User | `admin` username and SSH key supplied through Proxmox-generated user-data using `ciuser` and `sshkeys`; policy verified during first-boot finalization | `qm create --ciuser --sshkeys` |
| Hostname | Generated from the current Proxmox VM name, including after cloning and renaming | Proxmox-generated user-data |
| SSH | Public key only, no root login, `MaxAuthTries 3`, `LoginGraceTime 30s` | `/etc/ssh/sshd_config.d/99-harden.conf` |
| fail2ban | Aggressive `sshd` jail, 30m escalating bans, nftables actions, allow list from `FAIL2BAN_IGNORE_IPS` | `/etc/fail2ban/jail.local` |
| Kernel | Restricted kptr and ptrace, unprivileged BPF off, ICMP redirects off, strict `rp_filter`, SYN cookies | `/etc/sysctl.d/20-hardening.conf` |
| Updates | Unattended security upgrades, no automatic reboot | `/etc/apt/apt.conf.d/20auto-upgrades`, `52unattended-upgrades-local` |
| Swap | zram only, `min(ram / 2, 512)` with zstd, `vm.swappiness = 100` | `/etc/systemd/zram-generator.conf` |
| Disk | Root filesystem grows on first boot, `fstrim.timer` enabled | cloud-init `growpart` |
| Time | Timezone `America/Chicago` | cloud-init `timezone` |
| APPDATA (Docker) | Disk checked by WWN and serial, ext4 labelled `APPDATA`, mounted at `/mnt/appdata`; Docker will not start without it | `appdata-verify.service` |
| Docker | `data-root` on `/mnt/appdata/docker`, journald log driver, live restore, `admin` in the `docker` group | `/etc/docker/daemon.json` |
| Syslog | Volatile journal (64M), read at up to 25,000 messages per 60 seconds, and forwarded to `SYSLOG_SERVER:SYSLOG_PORT` over plain TCP with a memory-only queue and no local `/var/log` copy | `/etc/rsyslog.d/01-remote.conf` |
| RAM-only logging (syslog) | `/var/log` on a 128M tmpfs, fail2ban logging to the journal with its ban database in `/run` | `var-log.mount`, `/etc/fail2ban/fail2ban.local` |
| First boot | Self-checks the whole bootstrap, writes logs to `/home/admin/logs/`, then powers off; a failed boot stays running | `cloud-init-post-verify.service` |

Site-specific values such as `SYSLOG_SERVER`, `SYSLOG_PORT`,
`FAIL2BAN_IGNORE_IPS`, `APPDATA_WWN`, and `APPDATA_SERIAL` come from
`tools/.env`. `templates/deb_13.yml.tmpl` is the authority if this summary ever
falls behind.

### RAM-only logging (syslog variants)

A VM cloned from a syslog template never writes a log to its disk. `/var/log` is
a tmpfs mounted from `local-fs.target`, before cloud-init runs, so even
cloud-init's own log lands in RAM. The journal is volatile, the rsyslog
forwarding queue has no disk spool, and fail2ban logs to the journal instead of
a file. Nothing swaps to disk either: the only swap device is zram.

What you give up:

- **An unreachable collector loses messages.** The queue holds roughly 25,000
  messages in RAM and then discards, lowest severity first, rather than spooling
  to disk. There is no catch-up after a long outage.
- **A sustained log storm is rate-limited.** imjournal accepts 25,000 messages
  per 60-second window and reports excess messages as discarded.
- **Reboots lose all local history.** There is nothing to read after the fact
  except what the collector already received.
- **fail2ban forgets its bans on reboot.** The ban database lives in `/run`.
  Bans do survive a fail2ban restart.

Two things stay on disk on purpose. `/home/admin/logs/` is written once by the
first-boot bootstrap report and is how you debug a failed first boot. And the
template build boot itself writes `/var/log` normally, before the mount is
enabled — those files stay in the template image, shadowed and unused on every
clone.

## Basic logic of the repo

| Path | Purpose |
| --- | --- |
| `tools/.env` | Your local settings, copied from `tools/.env.example` and ignored by Git. Create this! |
| `templates/` | Shared cloud-init, Proxmox user-data, and creation-script templates. You don't need to access. |
| `tools/render_profiles.py` | Renders the template variations in memory. You don't need to access |
| `tools/build_template_bundle.py` | Validates the inputs and builds the Proxmox files. You don't need to access |
| `tools/create_proxmox_template.sh` | Main build command.  Run this to build the templates! |
| `build/` | Generated YAML and Proxmox creation scripts; ignored by Git. This is where your generated cloud-init files will live. |
| `assets/` and `docs/` | Docker signing-key material and supporting notes. |

The builder reads `.env`, renders all four templates, and writes the finished
bundle to `ARTIFACT_OUTPUT_DIR` (`./cloud-init/build` by default).

## Install Step #1: Create the cloud-init templates

Run these commands from the repository root on a Linux build machine. The
validator requires only Python 3 with PyYAML and Bash. Building also requires
OpenSSH's `ssh-keygen`. Proxmox tools and root access are not required on the
build machine.

Copy and edit the .env configuration file:

```bash
cp cloud-init/tools/.env.example cloud-init/tools/.env
chmod 0600 cloud-init/tools/.env
nano cloud-init/tools/.env
```

Review the VM IDs, name prefix, SSH public key, network bridge,
storage names, and Proxmox paths. `VMID_START` must begin a range of four unused
VM IDs.

Validate the configuration and templates:

```bash
./cloud-init/tools/validate.sh
git diff --check -- cloud-init
```

Build all four templates based on your .env file:

```bash
./cloud-init/tools/create_proxmox_template.sh
```

The build directory will contain four YAML files and four `create-*.sh`
scripts. Building does not change templates that already exist in Proxmox.

## Install Step #2: add template on Proxmox

The snippets go in the storage named by `SNIPPET_STORAGE_NAME` in
`cloud-init/tools/.env`. 

You can check the location on proxmox with:

```bash
pvesm path local:snippets/x
```

That prints the path the file `x` would have; drop the trailing `/x` and you
have the snippets directory. Use your own storage name in place of `local`.

### If you do not have SSH keys setup (Manually copy files)

Copy all eight files from `cloud-init/build/` into that snippets directory.

### If you have SSH keys setup

From the repository root on the build machine, set your Proxmox hostname and
storage name, then copy the generated bundle:

```bash
PROXMOX_HOST=pve.example.com
SNIPPET_STORAGE_NAME=local

SNIPPET_DIR="$(ssh "root@${PROXMOX_HOST}" pvesm path "${SNIPPET_STORAGE_NAME}:snippets/x")"
SNIPPET_DIR="${SNIPPET_DIR%/x}"

scp cloud-init/build/* "root@${PROXMOX_HOST}:${SNIPPET_DIR}/"
ssh "root@${PROXMOX_HOST}"
```

On the Proxmox host, change into the snippets directory you found above, then
run the script for each template you want:

| Template | Command |
| --- | --- |
| Plain | `bash create-deb13-plain-template.sh` |
| Plain + syslog | `bash create-deb13-plain-syslog-template.sh` |
| Docker | `bash create-deb13-docker-template.sh` |
| Docker + syslog | `bash create-deb13-docker-syslog-template.sh` |


The script downloads and verifies the Debian image, confirms the VM ID is
unused, and creates the selected Proxmox template. Keep the generated YAML
snippets available to Proxmox so its cloud-init drive can be regenerated.


A successful first boot records diagnostics and powers off. A failed first boot
stays running so it can be inspected from the Proxmox console.

## To Do List

- Replace plain TCP syslog with authenticated TLS or RELP.
- Add collector delivery confirmation and rsyslog queue monitoring.
- Add QEMU/Proxmox first-boot integration tests for every profile and APPDATA
  failure mode.
- Rootless Docker

## How do I use AI?

AI is not a substitute for understanding the code. I do not include code or features that I cannot explain, review, and maintain.

I use AI as a research and development assistant.  AI helps me explore ideas, reviews code, tests code in my own local virtual environments, and at times also generates code for me.

AI-assisted contributions are subject to the same validation process as my other contributions, including testing, manual review, and verification against relevant documentation and requirements. I remain responsible for all code committed to this repository.
