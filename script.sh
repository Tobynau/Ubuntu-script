#!/usr/bin/env bash
# cyberpatriot_hardener.sh
# Modern CyberPatriot-style hardening for Ubuntu 24.04 / Linux Mint 22.2
# - Asks for admin users (first is default and will NOT be modified)
# - Asks for regular users
# - Prompts to remove users not on the lists
# - Asks about SSH, TCP services, Apache
# - Applies safe, reversible hardening (backups + logs)
#
# Run as root.

set -euo pipefail
IFS=$'\n\t'

LOG=~/Desktop/Script.log
BACKUP_DIR=~/Desktop/backups
COMPARATIVE_DIR=~/Desktop/Comparatives
mkdir -p "$BACKUP_DIR" "$COMPARATIVE_DIR" ~/Desktop/logs
: > "$LOG"
chmod 600 "$LOG"

log() { echo "$(date +'%F %T') - $*" | tee -a "$LOG"; }

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Exiting."
  exit 1
fi

# Detect OS
. /etc/os-release
OS_NAME="$NAME"
OS_VER="$VERSION_ID"
log "Detected OS: $OS_NAME $OS_VER"

# Backup important files
FILES_TO_BACKUP=(/etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/login.defs /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/common-auth /etc/hosts /etc/apt/sources.list /etc/apache2/apache2.conf)
for f in "${FILES_TO_BACKUP[@]}"; do
  if [[ -e $f ]]; then
    cp -a "$f" "$BACKUP_DIR/" 2>/dev/null || true
  fi
done
log "Backed up key config files to $BACKUP_DIR."

# Helper prompts
ask_yesno() {
  while true; do
    read -rp "$1 (y/n): " ans
    case "$ans" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

is_valid_username() {
  local u=$1
  [[ "$u" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]]
}

# Get admin users
echo "Enter ADMIN users (space-separated). FIRST user will be default admin and will NOT be modified."
# Temporary IFS for this read: include space so input like "alice bob" splits correctly
IFS=$' \t\n' read -ra RAW_ADMIN_USERS
if [[ ${#RAW_ADMIN_USERS[@]} -eq 0 ]]; then
  echo "No admin users provided. Exiting."
  exit 1
fi

declare -a ADMIN_USERS=()
declare -A _seen=()
for raw in "${RAW_ADMIN_USERS[@]}"; do
  if ! is_valid_username "$raw"; then
    log "Invalid admin username: $raw"
    read -rp "Enter valid replacement (or leave empty to skip): " repl
    [[ -n "$repl" ]] && is_valid_username "$repl" && raw="$repl"
  fi
  [[ -z "${_seen[$raw]:-}" ]] && ADMIN_USERS+=("$raw") && _seen[$raw]=1
done
if [[ ${#ADMIN_USERS[@]} -eq 0 ]]; then
  echo "No valid admin usernames. Exiting."
  exit 1
fi
DEFAULT_ADMIN=${ADMIN_USERS[0]}
log "Admin users: ${ADMIN_USERS[*]}; default admin = $DEFAULT_ADMIN"

# Get regular users
echo "Enter REGULAR users (space-separated) to ensure exist / be managed."
# Temporary IFS for this read: include space so input like "alice bob" splits correctly
IFS=$' \t\n' read -ra RAW_REG_USERS
declare -a REG_USERS=()
_seen=()
for raw in "${RAW_REG_USERS[@]}"; do
  if ! is_valid_username "$raw"; then
    log "Invalid regular username: $raw"
    read -rp "Enter valid replacement (or leave empty to skip): " repl
    [[ -n "$repl" ]] && is_valid_username "$repl" && raw="$repl"
  fi
  [[ -z "${_seen[$raw]:-}" ]] && REG_USERS+=("$raw") && _seen[$raw]=1
done
log "Regular users: ${REG_USERS[*]}"

ensure_user_exists() {
  local u=$1
  local is_admin=${2:-no}
  if ! id "$u" &>/dev/null; then
    if ask_yesno "User '$u' does not exist. Create now?"; then
      adduser --gecos "" --disabled-password "$u" && log "Created $u"
    else
      log "Skipped creating $u"
      return
    fi
  fi

  # Admin group handling
  if [[ "$is_admin" == "yes" ]]; then
    usermod -aG sudo,adm,lpadmin,sambashare "$u" 2>/dev/null || true
    log "User $u added to admin groups."
  else
    [[ "$u" != "$DEFAULT_ADMIN" ]] && gpasswd -d "$u" sudo 2>/dev/null || true
    log "User $u removed from sudo if not default admin."
  fi

  # Password aging
  chage -M 90 -m 1 -W 14 "$u" 2>/dev/null || true
  log "Password aging set for $u."

  # SSH directory
  [[ ! -d "/home/$u/.ssh" ]] && mkdir -p "/home/$u/.ssh" && chown "$u:$u" "/home/$u/.ssh" && chmod 700 "/home/$u/.ssh"
}

# Ensure users
for u in "${ADMIN_USERS[@]}"; do
  ensure_user_exists "$u" yes
done
for u in "${REG_USERS[@]}"; do
  ensure_user_exists "$u" no
done

# Remove extra users
UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs || echo 1000)
UID_MAX=$(awk '/^UID_MAX/ {print $2}' /etc/login.defs || echo 60000)
mapfile -t CURRENT_USERS < <(awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '$3>=min && $3<=max {print $1}' /etc/passwd)
declare -A ALLOWED=()
for u in "${ADMIN_USERS[@]}"; do ALLOWED[$u]=1; done
for u in "${REG_USERS[@]}"; do ALLOWED[$u]=1; done
ALLOWED[$DEFAULT_ADMIN]=1
mapfile -t SYS_USERS < <(awk -F: -v min="$UID_MIN" '$3<min {print $1}' /etc/passwd)
for u in "${SYS_USERS[@]}"; do ALLOWED[$u]=1; done

declare -a EXTRA_USERS=()
for u in "${CURRENT_USERS[@]}"; do [[ -z "${ALLOWED[$u]:-}" ]] && EXTRA_USERS+=("$u"); done

if [[ ${#EXTRA_USERS[@]} -gt 0 ]]; then
  echo "Extra non-system users: ${EXTRA_USERS[*]}"
  if ask_yesno "Remove all extra users now?"; then
    for u in "${EXTRA_USERS[@]}"; do
      [[ "$u" == "$DEFAULT_ADMIN" ]] && continue
      userdel -r "$u" 2>/dev/null && log "Deleted $u"
    done
  fi
fi

# SSH hardening
if ask_yesno "Enable SSH?"; then
  apt-get update -qq && apt-get install -y -qq openssh-server
  systemctl enable --now ssh
  SSHD="/etc/ssh/sshd_config"
  cp -a "$SSHD" "$BACKUP_DIR/sshd_config.bak.$(date +%s)" || true
  if ask_yesno "Allow root login via SSH?"; then
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" "$SSHD"
  else
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" "$SSHD"
  fi
  if ask_yesno "Allow password authentication?"; then
    sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" "$SSHD"
  else
    sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" "$SSHD"
  fi
  if ask_yesno "Change SSH port to 2200?"; then
    sed -i "s/^#\?Port.*/Port 2200/" "$SSHD"
    ufw allow 2200/tcp
  else
    ufw allow ssh
  fi
  systemctl restart ssh
else
  systemctl disable --now ssh || true
  apt-get purge -y -qq openssh-server || true
  ufw deny ssh || true
fi

# Apache
if ask_yesno "Install/enable Apache?"; then
  apt-get install -y -qq apache2
  systemctl enable --now apache2
  APACHE_CONF="/etc/apache2/apache2.conf"
  cp -a "$APACHE_CONF" "$BACKUP_DIR/apache2.conf.bak.$(date +%s)" || true
  sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$APACHE_CONF" || echo "ServerTokens Prod" >> "$APACHE_CONF"
  sed -i 's/^ServerSignature.*/ServerSignature Off/' "$APACHE_CONF" || echo "ServerSignature Off" >> "$APACHE_CONF"
  find /etc/apache2 -type f -name '*.conf' -exec sed -i 's/Options Indexes/Options -Indexes/g' {} \; || true
  chown -R root:root /var/www
  systemctl restart apache2
else
  systemctl stop apache2 2>/dev/null || true
  systemctl disable apache2 2>/dev/null || true
  apt-get purge -y -qq apache2 apache2-utils apache2-bin apache2-data || true
  rm -rf /var/www/html/* 2>/dev/null || true
fi

# pwquality & PAM safe defaults
PWQ=/etc/security/pwquality.conf
cp -a "$PWQ" "$BACKUP_DIR/pwquality.conf.bak.$(date +%s)" 2>/dev/null || true
declare -A PWQ_KEYS=(["minlen"]="12" ["dcredit"]="-1" ["ucredit"]="-1" ["lcredit"]="-1" ["ocredit"]="-1" ["maxrepeat"]="3")
for k in "${!PWQ_KEYS[@]}"; do
  grep -qE "^\s*${k}\s*=" "$PWQ" && sed -i "s/^\s*${k}\s*=.*/${k} = ${PWQ_KEYS[$k]}/" "$PWQ" || echo "${k} = ${PWQ_KEYS[$k]}" >> "$PWQ"
done

CPW=/etc/pam.d/common-password
cp -a "$CPW" "$BACKUP_DIR/common-password.bak.$(date +%s)" 2>/dev/null || true
grep -q "pam_pwquality.so" "$CPW" || grep -q "pam_unix.so" "$CPW" && sed -i 's/^password\s\+\[success=1 default=ignore\]\s\+pam_unix.so.*/password [success=1 default=ignore] pam_unix.so obscure sha512/' "$CPW" || echo "password [success=1 default=ignore] pam_unix.so obscure sha512" >> "$CPW"

# UFW
if ask_yesno "Enable UFW?"; then
  apt-get install -y -qq ufw
  ufw default deny incoming
  ufw default allow outgoing
  grep -q '^Port 2200' /etc/ssh/sshd_config && ufw allow 2200/tcp || ufw allow ssh
  ufw --force enable
fi

# Fail2ban
if ask_yesno "Install fail2ban?"; then
  apt-get install -y -qq fail2ban
  systemctl enable --now fail2ban || true
  [[ ! -f /etc/fail2ban/jail.local ]] && cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
  systemctl restart fail2ban || true
fi

# Offensive tools
OFFENSIVE=(john hydra aircrack-ng ncat netcat-netcat-openbsd netcat-traditional ophcrack pyrit fcrackzip rarcrack)
for pkg in "${OFFENSIVE[@]}"; do
  dpkg -l 2>/dev/null | grep -q "^ii\s\+$pkg" && ask_yesno "Purge $pkg?" && apt-get purge -y -qq "$pkg" || true
done

# World-writable files
log "Scanning for world-writable files/directories..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > "$COMPARATIVE_DIR/world_writable_dirs.txt" 2>/dev/null || true
find / -xdev -type f -perm -0002 -print > "$COMPARATIVE_DIR/world_writable_files.txt" 2>/dev/null || true

# Media files
ask_yesno "Search for media files (mp3/mp4/jpg/etc)?" && find / -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.avi' -o -iname '*.mkv' \) > "$COMPARATIVE_DIR/media_files.txt" 2>/dev/null || true

# Snapshots
ss -tulpn > ~/Desktop/logs/listening_ports.log 2>/dev/null || true
ps aux > ~/Desktop/logs/processes.log 2>/dev/null || true
dpkg -l > ~/Desktop/logs/packages.log 2>/dev/null || true
cp -a /etc/passwd /etc/group /etc/sudoers /etc/ssh/sshd_config "$COMPARATIVE_DIR/" 2>/dev/null || true

# Summary
log "Hardening complete. Default admin: $DEFAULT_ADMIN"
log "Backups: $BACKUP_DIR, Comparative files: $COMPARATIVE_DIR, Logs: $LOG"
echo
echo "Review logs, backups, and comparative files before finalizing the system."
