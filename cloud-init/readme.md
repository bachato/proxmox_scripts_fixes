# Debian 13 cloud-init templates for Proxmox

## What this repo does

This is my workflow for building VM's using cloud-init, fully configured and ready to go in 2 mintues!

The files in this directory help you bild four hardened Debian 13 templates for Proxmox. Each
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

## Create the cloud-init templates

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

## Install a template on Proxmox

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
| Plain | `bash /mnt/pve/cloud-init/snippets/create-deb13-plain-template.sh` |
| Plain + syslog | `bash /mnt/pve/cloud-init/snippets/create-deb13-plain-syslog-template.sh` |
| Docker | `bash /mnt/pve/cloud-init/snippets/create-deb13-docker-template.sh` |
| Docker + syslog | `bash /mnt/pve/cloud-init/snippets/create-deb13-docker-syslog-template.sh` |

For example:

```bash
bash /mnt/pve/cloud-init/snippets/create-deb13-plain-template.sh
```

The script downloads and verifies the Debian image, confirms the VM ID is
unused, and creates the selected Proxmox template. Keep the generated YAML
snippets available to Proxmox so its cloud-init drive can be regenerated.

After cloning and starting a template, check first-boot provisioning inside the
guest:

```bash
sudo cloud-init status --long
```

A successful first boot records diagnostics and powers off. A failed first boot
stays running so it can be inspected from the Proxmox console.

## To Do List

- Replace plain TCP syslog with authenticated TLS or RELP.
- Add collector delivery confirmation and rsyslog queue monitoring.
- Add QEMU/Proxmox first-boot integration tests for every profile and APPDATA
  failure mode.
- Rootless Docker
