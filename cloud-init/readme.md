# Debian 13 cloud-init profiles for Proxmox

These profiles create a hardened Debian 13 VM, optionally with Docker and/or
remote syslog. They are intended to be attached as Proxmox custom vendor data
and run once on a clone's first boot.

## Supported profiles

| Profile | Docker | Remote syslog | APPDATA disk |
| --- | --- | --- | --- |
| `deb_13_plain.yml` | No | No | No |
| `deb_13_plain_syslog.yml` | No | TLS | No |
| `deb_13_docker.yml` | Yes | No | Required |
| `deb_13_docker_syslog.yml` | Yes | TLS | Required |

Files under `archive/` are historical references, not supported deployment
profiles.

All supported profiles:

- create the `admin` user and require a valid SSH public key supplied by
  Proxmox;
- disable root and password SSH login, install fail2ban, and validate sshd
  before declaring success;
- apply the kernel hardening and zram settings during bootstrap;
- install and verify the QEMU guest agent, unattended-upgrades, fail2ban, and
  zram swap;
- perform a full package upgrade during image bootstrap, then configure
  security-only unattended upgrades without automatic reboot;
- write final diagnostic logs to `/home/admin/logs/`; and
- power off only after every final validation succeeds.

If bootstrap fails, the VM deliberately remains running. Use its console and
the cloud-init logs to diagnose the failure.

## Docker APPDATA safety contract

Docker profiles require one dedicated, whole, unpartitioned data disk with:

- WWN `0x2000000000000001`;
- serial `APPDATA`; and
- either no existing signatures or an existing ext4 filesystem labeled
  `APPDATA`.

The bootstrap refuses to format a disk unless all of those checks pass. It
also rejects the root device chain, partitioned devices, and disks containing
unknown signatures. `/mnt/appdata` is a required mount; Docker cannot start
without it.

Do not attach that WWN and serial to any other disk in the same VM.

## Remote syslog behavior

The syslog profiles send RFC 5424 logs over server-authenticated TLS on TCP
port 6514. Before first boot, replace both occurrences of
`logs.example.invalid` with the DNS name in the receiver certificate.
Bootstrap fails while the placeholder remains.

The receiver's issuing CA must be trusted:

- Public CA: leave `SYSLOG_CA_FILE` empty in the provisioning block.
- Private CA: set `SYSLOG_CA_FILE` to the issuing CA's PEM certificate.

The provisioning block adds a private CA through cloud-init's `ca_certs`
module, and the finalizer runs `update-ca-certificates` before validating
rsyslog.

These profiles intentionally do not claim that logging is memory-only.
Journald uses up to 64 MiB of volatile storage, Debian's default local rsyslog
file actions are bypassed, and rsyslog has a root-only disk-assisted queue
bounded to 256 MiB for receiver outages. Cloud-init bootstrap logs and the
final diagnostic copies remain persistent.

The smoke-test message is tagged `cloud-init`. Confirm that it arrives at the
receiver before treating remote logging as operational.

## Create a Proxmox template

Run these commands as root on a Proxmox host. Adjust every value in the first
block. The repository checkout must contain commit
`dfcb7bfd871968497517c63a955aeb170eb9f263`.

The example retains the existing trust model: `admin` has passwordless sudo,
Docker profiles add `admin` to the Docker group, and Proxmox firewall
enforcement still depends on the host's firewall rules.

```bash
set -euo pipefail

# Required configuration
VMID=9000
NAME=debian13-template
PROFILE=deb_13_docker.yml
SSH_PUBLIC_KEY_FILE=/root/.ssh/id_ed25519.pub
REPO_ROOT=/root/proxmox_scripts_fixes

SNIPPET_STORAGE_NAME=local
SNIPPET_STORAGE_PATH=/var/lib/vz/snippets
ISO_STORAGE_PATH=/var/lib/vz/template/iso
VM_STORAGE_NAME=local-zfs
BRIDGE=vmbr100

# Required only for a syslog profile
SYSLOG_SERVER_NAME=
SYSLOG_CA_FILE=

# Optional sizing
CPU=4
MEM_MIN=1024
MEM_MAX=4096
APPDATA_DISK_SIZE=16

# Reviewed, immutable inputs
CLOUD_INIT_REF=dfcb7bfd871968497517c63a955aeb170eb9f263
IMAGE_BUILD=20260722-2547
IMAGE_NAME=debian-13-genericcloud-amd64-${IMAGE_BUILD}.qcow2
IMAGE_SHA512=735d1b2d0ef265a0c2323fdaa7d46e7bd7a1b984f73e8a785e638034bf07876e26374a9d809d713501270c071b3464d2ada0c5589f07742b95ed853cc6d48f45

NEEDS_APPDATA=0
NEEDS_SYSLOG=0
case "$PROFILE" in
  deb_13_plain.yml)
    PROFILE_SHA256=0063162b93792f0a556369057066477493980b643fee9c0656e6c7cce3ba55d3
    ;;
  deb_13_plain_syslog.yml)
    PROFILE_SHA256=90aa612019cb1856929c670ca981015d90b75aea46b19f32139fc1fd29d8ed52
    NEEDS_SYSLOG=1
    ;;
  deb_13_docker.yml)
    PROFILE_SHA256=2bac876a760563377069d7378264a26133e4b1153ff4c650cacbe75123bf12d0
    NEEDS_APPDATA=1
    ;;
  deb_13_docker_syslog.yml)
    PROFILE_SHA256=64968182356ac7fd01e26264016936d9070cd0d0f768eafec4a0cfa97985a153
    NEEDS_APPDATA=1
    NEEDS_SYSLOG=1
    ;;
  *)
    echo "Unsupported profile: $PROFILE" >&2
    exit 1
    ;;
esac

IMAGE_PATH=${ISO_STORAGE_PATH}/${IMAGE_NAME}
SNIPPET_PATH=${SNIPPET_STORAGE_PATH}/${PROFILE}

# Fail before changing Proxmox if an input or storage path is wrong.
test -d "$SNIPPET_STORAGE_PATH"
test -d "$ISO_STORAGE_PATH"
test -r "$SSH_PUBLIC_KEY_FILE"
ssh-keygen -l -f "$SSH_PUBLIC_KEY_FILE"
git -C "$REPO_ROOT" cat-file -e "${CLOUD_INIT_REF}^{commit}"

# Export and verify the reviewed profile, independent of the checked-out branch.
git -C "$REPO_ROOT" show "${CLOUD_INIT_REF}:cloud-init/${PROFILE}" >"$SNIPPET_PATH"
chmod 0600 "$SNIPPET_PATH"
printf '%s  %s\n' "$PROFILE_SHA256" "$SNIPPET_PATH" | sha256sum --check -

# Apply deterministic syslog customization after verifying the source profile.
if [ "$NEEDS_SYSLOG" -eq 1 ]; then
  case "$SYSLOG_SERVER_NAME" in
    ""|*[!A-Za-z0-9.-]*)
      echo "Set SYSLOG_SERVER_NAME to the receiver certificate's DNS name." >&2
      exit 1
      ;;
  esac

  sed -i \
    "s/logs\\.example\\.invalid/${SYSLOG_SERVER_NAME}/g" \
    "$SNIPPET_PATH"

  if [ -n "$SYSLOG_CA_FILE" ]; then
    test -r "$SYSLOG_CA_FILE"
    openssl x509 -in "$SYSLOG_CA_FILE" -noout -subject -issuer
    {
      printf '\nca_certs:\n  trusted:\n    - |\n'
      sed 's/^/        /' "$SYSLOG_CA_FILE"
    } >>"$SNIPPET_PATH"
  fi
fi

# Download and verify the reviewed Debian cloud image.
if [ ! -f "$IMAGE_PATH" ]; then
  curl --fail --location --proto '=https' --tlsv1.2 --retry 5 \
    --output "$IMAGE_PATH" \
    "https://cloud.debian.org/images/cloud/trixie/${IMAGE_BUILD}/${IMAGE_NAME}"
fi
printf '%s  %s\n' "$IMAGE_SHA512" "$IMAGE_PATH" | sha512sum --check -

if command -v cloud-init >/dev/null; then
  cloud-init schema --config-file "$SNIPPET_PATH"
fi

# Create the VM and inject the SSH key through Proxmox cloud-init data.
qm create "$VMID" \
  --name "$NAME" \
  --cores "$CPU" \
  --cpu host \
  --memory "$MEM_MAX" \
  --balloon "$MEM_MIN" \
  --net0 "virtio,bridge=${BRIDGE},queues=${CPU},firewall=1" \
  --scsihw virtio-scsi-single \
  --serial0 socket \
  --vga serial0 \
  --cicustom "vendor=${SNIPPET_STORAGE_NAME}:snippets/${PROFILE}" \
  --agent 1 \
  --ostype l26 \
  --localtime 0 \
  --tablet 0

qm set "$VMID" --rng0 source=/dev/urandom,max_bytes=1024,period=1000
qm set "$VMID" \
  --ciuser admin \
  --sshkeys "$SSH_PUBLIC_KEY_FILE" \
  --ipconfig0 ip=dhcp

qm importdisk "$VMID" "$IMAGE_PATH" "$VM_STORAGE_NAME"
ROOT_VOLUME="$(
  qm config "$VMID" |
    awk -F': ' '/^unused[0-9]+: / { print $2; exit }'
)"
test -n "$ROOT_VOLUME"
qm set "$VMID" \
  --scsi0 "${ROOT_VOLUME},ssd=1,discard=on,iothread=1"

if [ "$NEEDS_APPDATA" -eq 1 ]; then
  qm set "$VMID" \
    --scsi1 "${VM_STORAGE_NAME}:${APPDATA_DISK_SIZE},ssd=1,discard=on,iothread=1,backup=1,serial=APPDATA,wwn=0x2000000000000001"
fi

qm set "$VMID" \
  --ide2 "${VM_STORAGE_NAME}:cloudinit" \
  --boot order=scsi0
qm template "$VMID"
```

The source profile checksum is checked before the deterministic syslog
customization. The block also validates the final customized snippet when
`cloud-init` is available on the Proxmox host. To validate it explicitly:

```bash
cloud-init schema --config-file "$SNIPPET_PATH"
```

## First boot and operations

Clone the template, review its network settings, and start the clone. Package
installation can take several minutes.

- Success: the VM writes `/var/lib/cloud/instance/boot-success`, captures its
  diagnostic logs, and powers off.
- Failure: the success marker is absent and the VM stays running.

Keep the cloud-init drive attached. Cloud-init's per-instance state prevents
the bootstrap from rerunning on ordinary reboots, while the drive remains
available for correct instance metadata and future clones.

Useful diagnostics:

```bash
sudo cloud-init status --long
sudo journalctl -b -u cloud-final.service
sudo less /home/admin/logs/cloud-init-errors.log
sudo less /home/admin/logs/cloud-init-full.log
```

Ongoing unattended upgrades are security-only and never reboot
automatically. Schedule full OS upgrades, Docker upgrades, image pruning, and
required reboots through your normal maintenance or configuration-management
workflow.

## Editing and validation

The four deployable YAML files are generated. Edit
`templates/deb_13.yml.tmpl`, then render and validate:

```bash
python3 cloud-init/tools/render_profiles.py
cloud-init/tools/validate.sh
```

Validation covers cloud-init schema, YAML lint, embedded shell scripts, Docker
daemon JSON, the pinned Docker signing-key fingerprint, rsyslog syntax, SSH
baseline consistency, APPDATA destructive-operation guards, success gating,
and generated-file drift. CI runs the same validation in Debian 13.
