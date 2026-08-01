# Debian 13 cloud-init templates for Proxmox

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
| User | `admin` with passwordless sudo, locked password, and your SSH key | Proxmox cloud-init user data |
| SSH | Public key only, no root login, `MaxAuthTries 3`, `LoginGraceTime 30s` | `/etc/ssh/sshd_config.d/99-harden.conf` |
| fail2ban | Aggressive `sshd` jail, 30m escalating bans, nftables actions, allow list from `FAIL2BAN_IGNORE_IPS` | `/etc/fail2ban/jail.local` |
| Kernel | Restricted kptr and ptrace, unprivileged BPF off, ICMP redirects off, strict `rp_filter`, SYN cookies | `/etc/sysctl.d/20-hardening.conf` |
| Updates | Unattended security upgrades, no automatic reboot | `/etc/apt/apt.conf.d/20auto-upgrades`, `52unattended-upgrades-local` |
| Swap | zram only, `min(ram / 2, 512)` with zstd, `vm.swappiness = 100` | `/etc/systemd/zram-generator.conf` |
| Disk | Root filesystem grows on first boot, `fstrim.timer` enabled | cloud-init `growpart` |
| Time | Timezone `America/Chicago` | cloud-init `timezone` |
| APPDATA (Docker) | Disk checked by WWN and serial, ext4 labelled `APPDATA`, mounted at `/mnt/appdata`; Docker will not start without it | `appdata-verify.service` |
| Docker | `data-root` on `/mnt/appdata/docker`, journald log driver, live restore, `admin` in the `docker` group | `/etc/docker/daemon.json` |
| Syslog | Volatile journal (64M), forwarded to `SYSLOG_SERVER:SYSLOG_PORT` over plain TCP with a disk-backed queue and no local `/var/log` copy | `/etc/rsyslog.d/01-remote.conf` |
| First boot | Self-checks the whole bootstrap, writes logs to `/home/admin/logs/`, then powers off; a failed boot stays running | `cloud-init-post-verify.service` |

Site-specific values such as `SYSLOG_SERVER`, `SYSLOG_PORT`,
`FAIL2BAN_IGNORE_IPS`, `APPDATA_WWN`, and `APPDATA_SERIAL` come from
`tools/.env`. `templates/deb_13.yml.tmpl` is the authority if this summary ever
falls behind.

## Basic logic of the repo

| Path | Purpose |
| --- | --- |
| `tools/.env` | Your local settings, copied from `tools/.env.example` and ignored by Git. Create this! |
| `templates/` | Shared cloud-init, Proxmox user-data, and creation-script templates. You don't need to access. |
| `tools/render_profiles.py` | Renders the template variations. You don't need to access |
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

The build directory will contain five YAML files and four `create-*.sh`
scripts. Building does not change templates that already exist in Proxmox.

## Install Step #2: add template on Proxmox

### If you do not have SSH keys setup (Manually copy files)

Copy all nine files from `cloud-init/build/` to the Proxmox snippets folder set
by `PROXMOX_SNIPPET_PATH` in `cloud-init/tools/.env`.

### If you have SSH keys setup

From the repository root on the build machine, set your Proxmox hostname and
copy the generated bundle:

```bash
PROXMOX_HOST=pve.example.com
PROXMOX_SNIPPET_PATH=/mnt/pve/cloud-init/snippets

scp cloud-init/build/* "root@${PROXMOX_HOST}:${PROXMOX_SNIPPET_PATH}/"
ssh "root@${PROXMOX_HOST}"
```

The commands below use `/mnt/pve/cloud-init/snippets`. Replace that path if
your `PROXMOX_SNIPPET_PATH` setting is different.

On the Proxmox host, run the script for each template you want:

| Template | Command |
| --- | --- |
| Plain | `bash /snippets/create-deb13-plain-template.sh` |
| Plain + syslog | `bash /snippets/create-deb13-plain-syslog-template.sh` |
| Docker | `bash /snippets/create-deb13-docker-template.sh` |
| Docker + syslog | `bash /snippets/create-deb13-docker-syslog-template.sh` |


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

## How is AI used in this repo?

I use AI as a tool and a search engine.  I do not add code or features that I do not understand, or have not reviewed.
