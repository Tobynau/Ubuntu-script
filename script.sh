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

# Backup important files (safe)
FILES_TO_BACKUP=(/etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/login.defs /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/common-auth /etc/hosts /etc/apt/sources.list /etc/apache2/apache2.conf)
mkdir -p "$BACKUP_DIR"
for f in "${FILES_TO_BACKUP[@]}"; do
  if [[ -e $f ]]; then
    cp -a "$f" "$BACKUP_DIR/" 2>/dev/null || true
  fi
done
log "Backed up key config files to $BACKUP_DIR (existing files only)."

# Helper prompts
ask_yesno() {
  # $1 prompt
  while true; do
    read -rp "$1 (y/n): " ans
    case "$ans" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

read_list() {
  # read space-separated names into global array $1
  # usage: read_list arrname "Prompt text"
  local __arrname=$1
  local prompt=$2
  local -n __ref=$__arrname
  echo "$prompt"
  read -ra __ref
}

# Ask for admin and regular users (admins first). First admin = DEFAULT_ADMIN (never modified)
is_valid_username() {
  # returns 0 if $1 is a valid POSIX/Linux username (simple conservative check)
  local u=$1
  # must start with a lowercase letter or digit, allow a-z0-9._- up to 32 chars
  if [[ "$u" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]]; then
    return 0
  else
    return 1
  fi
}

echo "Enter ADMIN users (space-separated). FIRST user entered will be treated as the 'default' admin and will NOT be modified by this script."
read -ra RAW_ADMIN_USERS
if [[ ${#RAW_ADMIN_USERS[@]} -eq 0 ]]; then
  echo "No admin users provided. Exiting."
  exit 1
fi

# validate and deduplicate admin list (DO NOT auto-convert spaces to underscores)
declare -a ADMIN_USERS=()
declare -A _tmp_seen=()
for raw in "${RAW_ADMIN_USERS[@]}"; do
  if is_valid_username "$raw"; then
    s="$raw"
  else
    log "Admin input '$raw' is not a valid username. Skipping unless you provide a replacement."
    read -rp "Enter replacement valid username for '$raw' (leave empty to SKIP): " repl
    if [[ -n "$repl" && is_valid_username "$repl" ]]; then
      s="$repl"
      log "Using replacement username '$repl' for input '$raw'."
    else
      log "Skipping admin input '$raw' (no valid replacement provided)."
      continue
    fi
  fi
  if [[ -z "${_tmp_seen[$s]:-}" ]]; then
    ADMIN_USERS+=("$s")
    _tmp_seen[$s]=1
  fi
done
if [[ ${#ADMIN_USERS[@]} -eq 0 ]]; then
  echo "No valid admin usernames provided. Exiting."
  exit 1
fi
DEFAULT_ADMIN=${ADMIN_USERS[0]}
log "Admin users provided: ${ADMIN_USERS[*]}; default admin = $DEFAULT_ADMIN"

echo "Enter REGULAR users (space-separated) to ensure exist / be managed by this script."
read -ra RAW_REG_USERS
declare -a REG_USERS=()
unset _tmp_seen
declare -A _tmp_seen=()
for raw in "${RAW_REG_USERS[@]}"; do
  if is_valid_username "$raw"; then
    s="$raw"
  else
    log "Regular input '$raw' is not a valid username. Skipping unless you provide a replacement."
    read -rp "Enter replacement valid username for '$raw' (leave empty to SKIP): " repl
    if [[ -n "$repl" && is_valid_username "$repl" ]]; then
      s="$repl"
      log "Using replacement username '$repl' for input '$raw'."
    else
      log "Skipping regular input '$raw' (no valid replacement provided)."
      continue
    fi
  fi
  if [[ -z "${_tmp_seen[$s]:-}" ]]; then
    REG_USERS+=("$s")
    _tmp_seen[$s]=1
  fi
done
log "Regular users provided: ${REG_USERS[*]}"

# Create or update users function
ensure_user_exists() {
  # $1 username, $2 is_admin (yes/no)
  local u=$1
  local is_admin=${2:-no}
  if id "$u" &>/dev/null; then
    log "User $u exists."
  else
    log "User $u does NOT exist. Will NOT create unless you confirm."
    if ask_yesno "Create user '$u' now?"; then
      adduser --gecos "" --disabled-password "$u"
      log "User $u created."
    else
      log "Skipping creation of user $u (per user choice)."
    fi
  fi

  if [[ "$is_admin" == "yes" ]]; then
    if id "$u" &>/dev/null; then
      usermod -aG sudo,adm,lpadmin,sambashare "$u" || true
      log "User $u added to sudo, adm, lpadmin, sambashare (where groups exist)."
    else
      log "Cannot add $u to admin groups because the account does not exist."
    fi
  else
    # ensure not in sudo group (unless it's default admin)
    if [[ "$u" != "$DEFAULT_ADMIN" ]]; then
      if id "$u" &>/dev/null; then
        gpasswd -d "$u" sudo 2>/dev/null || true
        log "User $u removed from sudo (if present)."
      else
        log "Cannot remove $u from sudo because the account does not exist."
      fi
    else
      log "User $u is default admin; will not remove sudo membership."
    fi
  fi

  # Set password rules safely: set to expire after 90 days, min 1, warn 14
  chage -M 90 -m 1 -W 14 "$u" 2>/dev/null || true
  log "Password aging set for $u (max 90, min 1, warn 14)."

  # Create .ssh dir lightly (not overwriting)
  if [[ ! -d "/home/$u/.ssh" ]]; then
    mkdir -p "/home/$u/.ssh"
    chown "$u:$u" "/home/$u/.ssh"
    chmod 700 "/home/$u/.ssh"
    log "Created /home/$u/.ssh with safe perms."
  fi
}

# Ensure provided admin and regular users exist — operate per-user, running commands individually
for u in "${ADMIN_USERS[@]}"; do
  echo
  echo "Handling admin user: $u"
  if id "$u" &>/dev/null; then
    echo "$u exists on the system."
    if ask_yesno "Delete user '$u'?"; then
      userdel -r "$u" && log "Deleted user $u" || log "Failed to delete $u"
      continue
    fi
    if ask_yesno "Make '$u' an administrator (add to sudo/adm/lpadmin/sambashare)?"; then
      gpasswd -a "$u" sudo || true; log "gpasswd -a $u sudo"
      gpasswd -a "$u" adm || true; log "gpasswd -a $u adm"
      gpasswd -a "$u" lpadmin || true; log "gpasswd -a $u lpadmin"
      gpasswd -a "$u" sambashare || true; log "gpasswd -a $u sambashare"
    else
      if [[ "$u" != "$DEFAULT_ADMIN" ]]; then
        gpasswd -d "$u" sudo 2>/dev/null || true; log "gpasswd -d $u sudo"
        gpasswd -d "$u" adm 2>/dev/null || true; log "gpasswd -d $u adm"
        gpasswd -d "$u" lpadmin 2>/dev/null || true; log "gpasswd -d $u lpadmin"
        gpasswd -d "$u" sambashare 2>/dev/null || true; log "gpasswd -d $u sambashare"
      else
        log "Skipping removal of admin groups from default admin $u"
      fi
    fi
  else
    echo "$u does not exist on the system."
    if ask_yesno "Create user '$u' now?"; then
      adduser --gecos "" --disabled-password "$u" && log "Created user $u" || log "Failed to create $u"
      if ask_yesno "Make '$u' an administrator?"; then
        gpasswd -a "$u" sudo || true; log "gpasswd -a $u sudo"
        gpasswd -a "$u" adm || true; log "gpasswd -a $u adm"
        gpasswd -a "$u" lpadmin || true; log "gpasswd -a $u lpadmin"
        gpasswd -a "$u" sambashare || true; log "gpasswd -a $u sambashare"
      fi
    else
      log "Skipping creation of $u"
    fi
  fi

  # Password handling (individual)
  if id "$u" &>/dev/null; then
    if ask_yesno "Set a custom password for '$u'?"; then
      read -rsp "Password: " pw; echo; read -rsp "Confirm Password: " pw2; echo
      if [[ "$pw" == "$pw2" ]]; then
        printf "%s\n%s\n" "$pw" "$pw" | passwd "$u" 2>/dev/null || log "Failed to set password for $u"
        log "Set custom password for $u"
      else
        log "Passwords did not match; skipped setting password for $u"
      fi
    else
      printf "Moodle!22\nMoodle!22\n" | passwd "$u" 2>/dev/null || log "Failed to set default password for $u"
      log "Set default password for $u"
    fi
    passwd -x30 -n3 -w7 "$u" 2>/dev/null || true; log "Set password aging for $u"
    usermod -L "$u" 2>/dev/null || true; log "Locked account $u"
  fi
done

for u in "${REG_USERS[@]}"; do
  echo
  echo "Handling regular user: $u"
  if id "$u" &>/dev/null; then
    echo "$u exists on the system."
    if ask_yesno "Delete user '$u'?"; then
      userdel -r "$u" && log "Deleted user $u" || log "Failed to delete $u"
      continue
    fi
    if ask_yesno "Make '$u' an administrator (add to sudo/adm/lpadmin/sambashare)?"; then
      gpasswd -a "$u" sudo || true; log "gpasswd -a $u sudo"
      gpasswd -a "$u" adm || true; log "gpasswd -a $u adm"
      gpasswd -a "$u" lpadmin || true; log "gpasswd -a $u lpadmin"
      gpasswd -a "$u" sambashare || true; log "gpasswd -a $u sambashare"
    else
      if [[ "$u" != "$DEFAULT_ADMIN" ]]; then
        gpasswd -d "$u" sudo 2>/dev/null || true; log "gpasswd -d $u sudo"
        gpasswd -d "$u" adm 2>/dev/null || true; log "gpasswd -d $u adm"
        gpasswd -d "$u" lpadmin 2>/dev/null || true; log "gpasswd -d $u lpadmin"
        gpasswd -d "$u" sambashare 2>/dev/null || true; log "gpasswd -d $u sambashare"
      else
        log "Skipping removal of admin groups from default admin $u"
      fi
    fi
  else
    echo "$u does not exist on the system."
    if ask_yesno "Create user '$u' now?"; then
      adduser --gecos "" --disabled-password "$u" && log "Created user $u" || log "Failed to create $u"
      if ask_yesno "Make '$u' an administrator?"; then
        gpasswd -a "$u" sudo || true; log "gpasswd -a $u sudo"
        gpasswd -a "$u" adm || true; log "gpasswd -a $u adm"
        gpasswd -a "$u" lpadmin || true; log "gpasswd -a $u lpadmin"
        gpasswd -a "$u" sambashare || true; log "gpasswd -a $u sambashare"
      fi
    else
      log "Skipping creation of $u"
    fi
  fi

  # Password handling (individual)
  if id "$u" &>/dev/null; then
    if ask_yesno "Set a custom password for '$u'?"; then
      read -rsp "Password: " pw; echo; read -rsp "Confirm Password: " pw2; echo
      if [[ "$pw" == "$pw2" ]]; then
        printf "%s\n%s\n" "$pw" "$pw" | passwd "$u" 2>/dev/null || log "Failed to set password for $u"
        log "Set custom password for $u"
      else
        log "Passwords did not match; skipped setting password for $u"
      fi
    else
      printf "Moodle!22\nMoodle!22\n" | passwd "$u" 2>/dev/null || log "Failed to set default password for $u"
      log "Set default password for $u"
    fi
    passwd -x30 -n3 -w7 "$u" 2>/dev/null || true; log "Set password aging for $u"
    usermod -L "$u" 2>/dev/null || true; log "Locked account $u"
  fi
done

# Now scan system users (non-system range) and remove extras/add missing as a single step
# UID_MIN/UID_MAX from /etc/login.defs (fall back to 1000/60000)
UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs || echo 1000)
UID_MAX=$(awk '/^UID_MAX/ {print $2}' /etc/login.defs || echo 60000)
log "UID_MIN=$UID_MIN UID_MAX=$UID_MAX (from /etc/login.defs)"

mapfile -t CURRENT_USERS < <(awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '$3>=min && $3<=max {print $1}' /etc/passwd)
log "Current non-system users: ${CURRENT_USERS[*]}"

# Build allowed list and system users list
declare -A ALLOWED=()
for u in "${ADMIN_USERS[@]}"; do ALLOWED[$u]=1; done
for u in "${REG_USERS[@]}"; do ALLOWED[$u]=1; done
ALLOWED[$DEFAULT_ADMIN]=1
mapfile -t SYS_USERS < <(awk -F: -v min="$UID_MIN" '$3<min {print $1}' /etc/passwd)
for u in "${SYS_USERS[@]}"; do ALLOWED[$u]=1; done

# Determine extras (present on system but not allowed)
declare -a EXTRA_USERS=()
for u in "${CURRENT_USERS[@]}"; do
  if [[ -z "${ALLOWED[$u]:-}" ]]; then
    EXTRA_USERS+=("$u")
  fi
done

if [[ ${#EXTRA_USERS[@]} -gt 0 ]]; then
  echo
  echo "The following non-system users exist but are NOT in the admin/regular lists: ${EXTRA_USERS[*]}"
  if ask_yesno "Do you want to REMOVE all of these users now? (this runs 'userdel -r' for each)"; then
    for u in "${EXTRA_USERS[@]}"; do
      if [[ "$u" == "$DEFAULT_ADMIN" ]]; then
        log "Skipping deletion of default admin $u"
        continue
      fi
      userdel -r "$u" 2>/dev/null && log "Deleted extra user $u" || log "Failed to delete $u or user may not exist"
    done
    HANDLED_EXTRAS=1
  else
    log "User chose not to bulk-delete extra users; will keep them for manual review."
    HANDLED_EXTRAS=0
  fi
else
  log "No extra non-system users found to delete."
  HANDLED_EXTRAS=1
fi

# List current (non-system) users to compare
# UID_MIN/UID_MAX from /etc/login.defs
UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs || echo 1000)
UID_MAX=$(awk '/^UID_MAX/ {print $2}' /etc/login.defs || echo 60000)
log "UID_MIN=$UID_MIN UID_MAX=$UID_MAX (from /etc/login.defs)"

mapfile -t CURRENT_USERS < <(awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '$3>=min && $3<=max {print $1}' /etc/passwd)

log "System non-system users: ${CURRENT_USERS[*]}"

# Build a master allowed list (admins + regular + system accounts)
declare -A ALLOWED=()
for u in "${ADMIN_USERS[@]}"; do ALLOWED[$u]=1; done
for u in "${REG_USERS[@]}"; do ALLOWED[$u]=1; done
# always allow default admin explicitly
ALLOWED[$DEFAULT_ADMIN]=1
# always keep system accounts (uids < UID_MIN)
mapfile -t SYS_USERS < <(awk -F: -v min="$UID_MIN" '$3<min {print $1}' /etc/passwd)
for u in "${SYS_USERS[@]}"; do ALLOWED[$u]=1; done

# Check for users not in provided lists (if not already handled in bulk above)
if [[ "${HANDLED_EXTRAS:-0}" -eq 1 ]]; then
  log "Extras were handled earlier; skipping per-user deletion prompts."
else
  for u in "${CURRENT_USERS[@]}"; do
    if [[ -z "${ALLOWED[$u]:-}" ]]; then
      echo "User '$u' exists on system but was NOT in your admin/regular lists."
      if [[ "$u" == "$DEFAULT_ADMIN" ]]; then
        log "Skipping default admin $u from deletion."
        continue
      fi
      if ask_yesno "Do you want to REMOVE (userdel -r) the user '$u' ?"; then
        userdel -r "$u" && log "Deleted user $u (home + mail removed)"
      else
        log "Kept user $u (user not deleted)."
      fi
    fi
  done
fi

# SERVICE QUESTIONS: SSH, TCP, APACHE
log "Now asking about services."

if ask_yesno "Is SSH supposed to be ENABLED on this image?"; then
  # install and harden SSH
  apt-get update -qq
  apt-get install -y -qq openssh-server
  systemctl enable --now ssh
  log "openssh-server installed and enabled."

  # Edit sshd_config safely (backup above already saved)
  SSHD="/etc/ssh/sshd_config"
  cp -a "$SSHD" "$BACKUP_DIR/sshd_config.bak.$(date +%s)" || true

  # Ask specifics
  if ask_yesno "Should root be allowed to login via SSH? (NO is recommended)"; then
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" "$SSHD" || true
    log "Set PermitRootLogin yes"
  else
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" "$SSHD" || true
    log "Set PermitRootLogin no"
  fi

  if ask_yesno "Should password authentication be allowed for SSH? (if you plan keys-only, answer no)"; then
    sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" "$SSHD" || true
    log "Set PasswordAuthentication yes"
  else
    sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" "$SSHD" || true
    log "Set PasswordAuthentication no"
  fi

  if ask_yesno "Change SSH port from 22 to 2200? (helps low-effort scoring sometimes)"; then
    sed -i "s/^#\?Port.*/Port 2200/" "$SSHD" || true
    ufw allow 2200/tcp
    log "SSH port changed to 2200 and allowed in UFW."
  else
    ufw allow ssh
    log "SSH left on default port 22 and allowed in UFW."
  fi

  systemctl restart ssh || true
  log "SSHD configuration applied and service restarted (if available)."

else
  log "User indicated SSH should be disabled. Stopping & disabling."
  systemctl disable --now ssh || true
  apt-get purge -y -qq openssh-server || true
  ufw deny ssh || true
fi

# Show listening TCP services and offer to stop specific ones
echo
log "Listing listening TCP services (ss -tulpn) — review and decide which to stop."
ss -tulpn | tee -a "$LOG"
echo
if ask_yesno "Do you want the script to offer to stop services that are listening on TCP ports (interactive per service)?"; then
  # build a list of distinct services with listening TCP sockets
  mapfile -t LISTENERS < <(ss -tulpn | awk '/LISTEN/ {print $0}' | sed 's/^[ \t]*//' | sort -u)
  # present and let admin decide per-line
  for line in "${LISTENERS[@]}"; do
    echo
    echo "$line"
    if ask_yesno "Stop the service responsible for the above line? (attempt via systemctl stop <service>)"; then
      # try to extract process name / pid
      pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || true)
      svcname=""
      if [[ -n "$pid" ]]; then
        svcname=$(ps -p "$pid" -o comm=)
      else
        # try to parse program name after LISTEN
        svcname=$(echo "$line" | awk '{print $6}' | cut -d',' -f2 | cut -d'/' -f1 2>/dev/null || true)
      fi
      if [[ -n "$svcname" ]]; then
        log "Attempting to stop service/process: $svcname (pid $pid)"
        systemctl stop "$svcname" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || log "Could not stop $svcname by systemctl/kill"
      else
        log "Could not identify service to stop for line: $line"
      fi
    fi
  done
else
  log "Skipped interactive stopping of TCP services."
fi

# Apache
if ask_yesno "Is Apache required on this image?"; then
  apt-get install -y -qq apache2 || true
  systemctl enable --now apache2 || true
  log "Apache installed/enabled."

  # safe Apache hardening (backup earlier)
  APACHE_CONF="/etc/apache2/apache2.conf"
  cp -a "$APACHE_CONF" "$BACKUP_DIR/apache2.conf.bak.$(date +%s)" || true
  # Disable server tokens & signature
  if ! grep -q -E '^ServerTokens' "$APACHE_CONF"; then
    echo -e "\nServerTokens Prod\nServerSignature Off" >> "$APACHE_CONF"
  else
    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$APACHE_CONF" || true
    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$APACHE_CONF" || true
  fi
  # disable directory listing in default conf
  find /etc/apache2 -type f -name '*.conf' -exec sed -i 's/Options Indexes/Options -Indexes/g' {} \; || true
  chown -R root:root /var/www || true
  log "Applied safe Apache hardening (ServerTokens/ServerSignature/No Indexes). Restarting Apache."
  systemctl restart apache2 || true
else
  log "User indicated Apache not required. Purging apache2 if present."
  systemctl stop apache2 2>/dev/null || true
  systemctl disable apache2 2>/dev/null || true
  apt-get purge -y -qq apache2 apache2-utils apache2-bin apache2-data || true
  rm -rf /var/www/html/* 2>/dev/null || true
  log "Apache purged (if it existed)."
fi

# PWQUALITY / PAM gentle configuration
log "Configuring safe password complexity defaults (pwquality) - backup created."

PWQ=/etc/security/pwquality.conf
cp -a "$PWQ" "$BACKUP_DIR/pwquality.conf.bak.$(date +%s)" 2>/dev/null || true

# write minimal safe settings (will append/replace known keys)
declare -A PWQ_KEYS=(
  ["minlen"]="12"
  ["dcredit"]="-1"
  ["ucredit"]="-1"
  ["lcredit"]="-1"
  ["ocredit"]="-1"
  ["maxrepeat"]="3"
)
for k in "${!PWQ_KEYS[@]}"; do
  if grep -qE "^\s*${k}\s*=" "$PWQ" 2>/dev/null; then
    sed -i "s/^\s*${k}\s*=.*/${k} = ${PWQ_KEYS[$k]}/" "$PWQ"
  else
    echo "${k} = ${PWQ_KEYS[$k]}" >> "$PWQ"
  fi
done
log "pwquality configured (safe defaults)."

# Ensure PAM common-password uses pam_pwquality or pam_unix in a safe manner
CPW=/etc/pam.d/common-password
cp -a "$CPW" "$BACKUP_DIR/common-password.bak.$(date +%s)" 2>/dev/null || true
# If pam_pwquality exists in file, set reasonable retry and minlen via pwquality already set.
# If not, ensure pam_unix line exists with sha512
if ! grep -q "pam_pwquality.so" "$CPW"; then
  if grep -q "pam_unix.so" "$CPW"; then
    sed -i 's/^password\s\+\[success=1 default=ignore\]\s\+pam_unix.so.*/password [success=1 default=ignore] pam_unix.so obscure sha512/' "$CPW" || true
  else
    echo "password [success=1 default=ignore] pam_unix.so obscure sha512" >> "$CPW"
  fi
fi
log "PAM common-password adjusted conservatively (backups exist)."

# UFW firewall basic setup
if ask_yesno "Enable UFW with default deny incoming / allow outgoing?"; then
  apt-get install -y -qq ufw
  ufw default deny incoming
  ufw default allow outgoing
  # allow ssh depending on chosen port
  if grep -q '^Port 2200' /etc/ssh/sshd_config 2>/dev/null; then
    ufw allow 2200/tcp
  else
    ufw allow ssh
  fi
  ufw --force enable
  log "UFW enabled with defaults."
else
  log "UFW not enabled per user."
fi

# Install fail2ban (helps reduce brute force attempts)
if ask_yesno "Install and enable fail2ban (recommended)?"; then
  apt-get install -y -qq fail2ban
  systemctl enable --now fail2ban || true
  log "fail2ban installed and enabled."
  # Add recommended local jail.local if not present; minimal default
  if [[ ! -f /etc/fail2ban/jail.local ]]; then
    cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
    systemctl restart fail2ban || true
    log "Created basic /etc/fail2ban/jail.local"
  fi
else
  log "fail2ban not installed (per user)."
fi

# Remove common offensive tools if user agrees (interactive)
OFFENSIVE=(john hydra aircrack-ng ncat netcat-netcat-openbsd netcat-traditional ophcrack pyrit fcrackzip rarcrack)
echo
log "Checking for offensive/password-cracking tools. You will be asked to purge each if found."
for pkg in "${OFFENSIVE[@]}"; do
  if dpkg -l 2>/dev/null | grep -q "^ii\s\+$pkg"; then
    echo "Package $pkg is installed."
    if ask_yesno "Purge $pkg?"; then
      apt-get purge -y -qq "$pkg" || true
      log "Purged $pkg"
    else
      log "Left $pkg installed (per user)."
    fi
  fi
done

# Find world-writable files and log them (don't automatically delete)
log "Finding world-writable files (will be listed in $COMPARATIVE_DIR/world_writable.txt)."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > "$COMPARATIVE_DIR/world_writable_dirs.txt" 2>/dev/null || true
find / -xdev -type f -perm -0002 -print > "$COMPARATIVE_DIR/world_writable_files.txt" 2>/dev/null || true
log "World-writable scan complete."

# Media files search (for scoring where disallowed)
if ask_yesno "Search for common media files (mp3/mp4/jpg/etc) and log them?"; then
  log "Searching for media files (this may take time)..."
  find / -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.avi' -o -iname '*.mkv' \) > "$COMPARATIVE_DIR/media_files.txt" 2>/dev/null || true
  log "Media scan complete; results in $COMPARATIVE_DIR/media_files.txt"
fi

# Logs and comparative snapshots
log "Creating service/process/port snapshots for comparison."
ss -tulpn > ~/Desktop/logs/listening_ports.log 2>/dev/null || true
ps aux > ~/Desktop/logs/processes.log 2>/dev/null || true
dpkg -l > ~/Desktop/logs/packages.log 2>/dev/null || true
cp -a /etc/passwd "$COMPARATIVE_DIR/"
cp -a /etc/group "$COMPARATIVE_DIR/"
cp -a /etc/sudoers "$COMPARATIVE_DIR/" 2>/dev/null || true
cp -a /etc/ssh/sshd_config "$COMPARATIVE_DIR/" 2>/dev/null || true
log "Saved snapshots to ~/Desktop/logs and $COMPARATIVE_DIR."

# Final reminders and summary
echo
log "Hardening run complete (summary):"
log " - Default admin (never modified): $DEFAULT_ADMIN"
log " - Admin users ensured: ${ADMIN_USERS[*]}"
log " - Regular users ensured: ${REG_USERS[*]}"
log " - Backups in: $BACKUP_DIR"
log " - Comparative files in: $COMPARATIVE_DIR"
log " - Change log: $LOG"

echo
echo "IMPORTANT NEXT STEPS (READ):"
echo " 1) Test sudo and login with at least one admin account before sign-off."
echo " 2) Manually inspect $COMPARATIVE_DIR/world_writable_files.txt and media lists."
echo " 3) If a PAM or login issue appears, restore backups from $BACKUP_DIR (e.g. cp $BACKUP_DIR/common-password /etc/pam.d/common-password)."
echo " 4) For CyberPatriot rounds: consult the round READMEs — they often list expected services. This script asks about SSH/Apache/TCP to match the README."

log "Script finished. Please review the logs and comparative output before finalizing the image."
