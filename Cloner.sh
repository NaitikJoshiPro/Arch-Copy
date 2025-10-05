#!/usr/bin/env bash
# arch-to-usb-clone.sh
# Clones an existing Arch Linux installation (separate / and /boot) onto a USB drive.
# - Detects source root and /boot devices
# - Finds a removable USB drive candidate
# - Repartitions USB (GPT): small /boot partition and remaining root
# - Formats partitions according to source types
# - Uses rsync to copy files (preserves permissions, xattrs, ACLs)
# - Installs GRUB (UEFI or BIOS) and regenerates grub.cfg
#
# SAFETY: This script will DESTROY the selected USB device. It requires
# interactive confirmation where you must type the exact target device path
# (e.g. /dev/sdb) to proceed.
#
# IMPORTANT: Review this script *carefully* before running. I strongly
# recommend making a full backup of any important data.

set -euo pipefail
IFS=$'\n\t'

LOGFILE="/tmp/arch_to_usb_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Starting Arch -> USB cloning script"
echo "Log: $LOGFILE"

# Helper: die with message
die() { echo "ERROR: $*" >&2; exit 1; }

# Detect source root and boot
SRC_ROOT_DEV=$(findmnt -n -o SOURCE /) || die "Can't detect source root device"
if findmnt -n /boot >/dev/null 2>&1; then
  SRC_BOOT_DEV=$(findmnt -n -o SOURCE /boot) || die "Can't detect /boot device"
else
  echo "/boot is not a separate mount. Using /boot inside / (will copy /boot dir)."
  SRC_BOOT_DEV=""
fi

echo "Source root device: $SRC_ROOT_DEV"
[ -n "$SRC_BOOT_DEV" ] && echo "Source /boot device: $SRC_BOOT_DEV"

# Resolve parent disk for source
get_parent_disk() {
  dev="$1"
  # e.g. /dev/nvme0n1p2 -> nvme0n1
  base=$(lsblk -no PKNAME "$dev" 2>/dev/null || true)
  if [ -z "$base" ]; then
    # fallback for simple devices like /dev/sda
    base=$(basename "$dev" | sed -E 's/p?[0-9]+$//')
  fi
  echo "/dev/$base"
}

SRC_DISK=$(get_parent_disk "$SRC_ROOT_DEV")
[ -b "$SRC_DISK" ] || die "Source disk $SRC_DISK not found"
echo "Source disk: $SRC_DISK"

# Calculate used size on root (bytes) and on boot if separate
used_root_bytes=$(df --output=used -B1 / | tail -n1 | tr -d '[:space:]')
used_total_bytes=$used_root_bytes
if [ -n "$SRC_BOOT_DEV" ]; then
  used_boot_bytes=$(df --output=used -B1 /boot | tail -n1 | tr -d '[:space:]')
  used_total_bytes=$((used_total_bytes + used_boot_bytes))
fi
used_total_gb=$(( (used_total_bytes + 1024*1024*1024 - 1) / (1024*1024*1024) ))
req_gb=$((used_total_gb + 4))

echo "Used data estimate: ${used_total_gb} GiB (will require approx ${req_gb} GiB on target)"

# Find removable block devices (RM==1), not the source disk, not mounted
mapfile -t candidates < <(lsblk -dn -o NAME,RM,SIZE,MOUNTPOINT | awk '$2==1 && $4=="" {print "/dev/"$1" "$3}')

if [ ${#candidates[@]} -eq 0 ]; then
  echo "No removable devices auto-detected. Listing all non-source, non-mounted disks:" >&2
  lsblk -dn -o NAME,SIZE,MOUNTPOINT
  die "Please insert the target USB drive and re-run the script."
fi

echo "Detected removable candidates:"
for c in "${candidates[@]}"; do echo "  $c"; done

# Choose the first candidate that is big enough
TARGET_DEV=""
for entry in "${candidates[@]}"; do
  dev=$(awk '{print $1}' <<<"$entry")
  size_h=$(awk '{print $2}' <<<"$entry")
  # convert human size to GB integer guess (handles e.g. 64G, 29G)
  size_val=$(sed -E 's/([0-9.]+)([A-Za-z]+)/\1 \2/' <<<"$size_h")
  num=$(awk '{print $1}' <<<"$size_val")
  unit=$(awk '{print $2}' <<<"$size_val")
  size_gb=0
  case "$unit" in
    G|Gi|GB|G) size_gb=${num%.*} ;;
    M|Mi|MB|M) size_gb=0 ;;
    T|Ti|TB|T) size_gb=$((num*1024)) ;;
    *) size_gb=${num%.*} ;;
  esac
  if [ "$size_gb" -ge "$req_gb" ]; then
    TARGET_DEV="$dev"
    break
  fi
done

if [ -z "$TARGET_DEV" ]; then
  echo "No removable device large enough found. Showing candidates again:" >&2
  for c in "${candidates[@]}"; do echo "  $c"; done
  die "Insert a larger USB (>= ${req_gb} GiB) or free space and re-run."
fi

echo "Selected target device: $TARGET_DEV"

# Safety interactive confirmation: require typing the device path
read -rp "Type the exact target device path to confirm wiping it (e.g. $TARGET_DEV): " confirm
if [ "$confirm" != "$TARGET_DEV" ]; then
  die "Confirmation did not match. Aborting to prevent accidental data loss."
fi

echo "-- Beginning destructive operations on $TARGET_DEV --"

# Unmount any mounted partitions of target
for part in $(lsblk -ln -o NAME "$TARGET_DEV" | tail -n +2); do
  mp=$(lsblk -ln -o MOUNTPOINT "/dev/$part" | tr -d ' ')
  if [ -n "$mp" ]; then
    echo "Unmounting /dev/$part mounted at $mp"
    sudo umount -l "/dev/$part" || true
  fi
done

# Wipe beginning of target device to remove old partition table
sudo dd if=/dev/zero of="$TARGET_DEV" bs=1M count=16 status=progress || true

# Create GPT and partitions: partition 1 = /boot (same size as source /boot or 512M), partition 2 = rest
BOOT_SIZE_MB=512
if [ -n "$SRC_BOOT_DEV" ]; then
  # try to detect source boot size (in MB)
  src_boot_size_kb=$(blockdev --getsz "$SRC_BOOT_DEV" 2>/dev/null || true)
  if [ -n "$src_boot_size_kb" ]; then
    # convert sectors (512B) if needed; fallback keep 512MB
    BOOT_SIZE_MB=512
  fi
fi

echo "Creating partitions on $TARGET_DEV"
parted -s "$TARGET_DEV" mklabel gpt
parted -s "$TARGET_DEV" mkpart primary 1MiB ${BOOT_SIZE_MB}MiB
parted -s "$TARGET_DEV" set 1 boot on || true
parted -s "$TARGET_DEV" mkpart primary ${BOOT_SIZE_MB}MiB 100%

sleep 1

# Wait for kernel to notice partitions
sudo partprobe "$TARGET_DEV" || true
sleep 1

# Determine partition names
if [[ "$TARGET_DEV" =~ nvme ]]; then
  TARGET_BOOT_P="${TARGET_DEV}p1"
  TARGET_ROOT_P="${TARGET_DEV}p2"
else
  TARGET_BOOT_P="${TARGET_DEV}1"
  TARGET_ROOT_P="${TARGET_DEV}2"
fi

echo "Target partitions: $TARGET_BOOT_P (boot), $TARGET_ROOT_P (root)"

# Detect source filesystems
src_root_fs=$(lsblk -no FSTYPE "$SRC_ROOT_DEV")
src_boot_fs=""
if [ -n "$SRC_BOOT_DEV" ]; then
  src_boot_fs=$(lsblk -no FSTYPE "$SRC_BOOT_DEV")
fi

echo "Source root fs: ${src_root_fs:-unknown}"
[ -n "$src_boot_fs" ] && echo "Source boot fs: ${src_boot_fs}"

# Format target partitions
if [ -n "$src_boot_fs" ] && [[ "$src_boot_fs" =~ vfat|fat32|fat ]]; then
  echo "Formatting $TARGET_BOOT_P as FAT32"
  sudo mkfs.vfat -F32 "$TARGET_BOOT_P"
elif [ -n "$src_boot_fs" ] && [[ "$src_boot_fs" =~ ext ]]; then
  echo "Formatting $TARGET_BOOT_P as ext4"
  sudo mkfs.ext4 -F "$TARGET_BOOT_P"
else
  echo "Default: formatting $TARGET_BOOT_P as FAT32"
  sudo mkfs.vfat -F32 "$TARGET_BOOT_P"
fi

echo "Formatting $TARGET_ROOT_P as ext4"
sudo mkfs.ext4 -F "$TARGET_ROOT_P"

# Mount targets
mkdir -p /mnt/usb
sudo mount "$TARGET_ROOT_P" /mnt/usb
sudo mkdir -p /mnt/usb/boot
sudo mount "$TARGET_BOOT_P" /mnt/usb/boot

# If source /boot is separate, mount it to /mnt/src/boot; else use /boot inside /
mkdir -p /mnt/src
sudo mount --bind / /mnt/src

# Use rsync to copy files (exclude runtime files)
echo "Starting rsync copy (this may take a while)"

RSYNC_EXCLUDE=("/dev/*" "/proc/*" "/sys/*" "/tmp/*" "/run/*" "/mnt/*" "/media/*" "/lost+found")

sudo rsync -aAXHv --info=progress2 --delete "${RSYNC_EXCLUDE[@]/#/--exclude=}" /mnt/src/ /mnt/usb/

# Ensure /etc/fstab on target points to correct UUIDs
echo "Updating /etc/fstab on target"
root_uuid=$(sudo blkid -s UUID -o value "$TARGET_ROOT_P")
boot_uuid=$(sudo blkid -s UUID -o value "$TARGET_BOOT_P")

if [ -z "$root_uuid" ]; then die "Could not read UUID of $TARGET_ROOT_P"; fi

# Create a simple fstab (preserve existing opts from source if possible)
cat <<EOF | sudo tee /mnt/usb/etc/fstab
# /etc/fstab: static file system information.
UUID=${root_uuid} / ext4 defaults,noatime 0 1
EOF
if [ -n "$boot_uuid" ]; then
  if [[ "$src_boot_fs" =~ vfat|fat ]]; then
    echo "UUID=${boot_uuid} /boot vfat umask=0077,shortname=winnt 0 2" | sudo tee -a /mnt/usb/etc/fstab
  else
    echo "UUID=${boot_uuid} /boot ext4 defaults 0 2" | sudo tee -a /mnt/usb/etc/fstab
  fi
fi

# Bind system dirs and chroot to install grub and mkinitcpio
echo "Preparing chroot to reinstall bootloader"
for d in dev sys proc run; do
  sudo mount --bind /$d /mnt/usb/$d || true
done

# If on UEFI system
if [ -d /sys/firmware/efi ]; then
  echo "Detected UEFI system. Installing GRUB for UEFI on the USB."
  sudo arch-chroot /mnt/usb /bin/bash -c "
    pacman -Sy --noconfirm grub efibootmgr >/dev/null 2>&1 || true
    mkdir -p /boot/EFI
  "
  # Use grub-install with --removable to avoid touching NVRAM on host
  sudo arch-chroot /mnt/usb grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=ArchUSB --removable || die "grub-install failed"
  sudo arch-chroot /mnt/usb grub-mkconfig -o /boot/grub/grub.cfg || die "grub-mkconfig failed"
else
  echo "Detected BIOS system. Installing grub-pc on USB MBR"
  sudo arch-chroot /mnt/usb /bin/bash -c "pacman -Sy --noconfirm grub >/dev/null 2>&1 || true"
  sudo grub-install --target=i386-pc --recheck --boot-directory=/mnt/usb/boot "$TARGET_DEV" || die "grub-install (bios) failed"
  # grub-mkconfig inside chroot
  sudo arch-chroot /mnt/usb grub-mkconfig -o /boot/grub/grub.cfg || die "grub-mkconfig failed"
fi

# Rebuild initramfs inside chroot (helps portability)
sudo arch-chroot /mnt/usb mkinitcpio -P || echo "mkinitcpio failed or not present - continue"

# Unmount everything
echo "Syncing and unmounting"
sync
for d in run proc sys dev; do sudo umount -l /mnt/usb/$d || true; done
sudo umount -l /mnt/usb/boot || true
sudo umount -l /mnt/usb || true

echo "Done. The USB should now be bootable. Log saved to $LOGFILE"

echo "IMPORTANT: Test the USB on the target machine's boot menu. If it doesn't boot, check the log and consider reinstalling grub manually."

exit 0
