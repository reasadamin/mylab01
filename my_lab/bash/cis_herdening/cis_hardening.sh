#!/bin/bash
###################################################################################################
#											          #
# ol8-cis-hardening.sh							                          #
# 												  #
# Authors: Shamrat								                  #
#											          #
# Description: This script will harden OCI Oracle Linux 8 servers according to CIS benchmark      #
#											          #                                       	
###################################################################################################

[[ ! -d cis_script_logs_backups ]] && mkdir cis_script_logs_backups

cd cis_script_logs_backups

exec >> ol8-cis-hardening-script.log 2>&1

echo "~~~~~~~~~~~~~~~~~~~~~~Start - $(date +"%F %T")~~~~~~~~~~~~~~~~~~~~~~"

function msg {
	echo "$(date "+%F %T") $1"
}

function bak {
	cp -pn $1 $(basename $1).$(date +%F).bak
}

# Disabling cramfs
	msg "Disabling module: cramfs"
	echo "install cramfs /bin/false blacklist cramfs" > "/etc/modprobe.d/cramfs.conf"
	modprobe -r cramfs

# Disabling usb storage 
	msg "Disabling module: usb-storage"
        echo "install usb-storage /bin/true" > "/etc/modprobe.d/usb-storage.conf"
	rmmod usb-storage

	# Disabling wireless device, (if WiFi is enabled)
wifi_status=$(nmcli radio all | grep -i "enabled" | awk '{print $2}')

if [ "$wifi_status" == "enabled" ]; then
	msg "Disabling wifi service"
	nmcli radio all off
fi

# Add nodev mount option - home
if (mount | grep -E "\s/home\s" | grep -v nodev > /dev/null 2>&1); then
	msg "Adding mount option rw,nosuid,nodev,relatime for /home"
	bak /etc/fstab
	perl -i -pe 's/defaults/defaults,rw,nosuid,nodev,relatime/ if /\/home/' /etc/fstab
	mount -o remount /home
fi

# Add nodev mount option - var
if (mount | grep -E "\s/var\s" | grep -v nodev > /dev/null 2>&1); then
	msg "Adding mount option rw,nosuid,nodev,noexec,relatime for /var"
	bak /etc/fstab
	perl -i -pe 's/defaults/defaults,rw,nosuid,nodev,noexec,relatime/ if /\/var/' /etc/fstab
	mount -o remount /var
fi

# Add nodev mount option - tmp

if (mount | grep -E "\s/tmp\s" | grep -v nodev > /dev/null 2>&1); then
	msg "Adding mount option rw,nosuid,nodev,noexec,relatime for /tmp"
	bak /etc/fstab
	perl -i -pe 's/defaults/defaults,rw,nosuid,nodev,noexec,relatime/ if /\/tmp/' /etc/fstab
	mount -o remount /tmp
fi

# Add nodev and nosuid mount options - /tmp

for mo in nodev nosuid; do
	if (mount | grep -E "\s/tmp\s" | grep -v $mo > /dev/null 2>&1); then
		msg "Adding mount option $mo for /tmp"
		bak /etc/fstab
		export mo
		perl -i -pe 's/(default\S+)/${1},$ENV{'mo'}/ if /\/tmp /' /etc/fstab
		upd_tmp=1
	fi
done

[[ $upd_tmp ]] && mount -o remount /tmp

# tmpfs configuration
(msg "Adding mount options for tmpfs" && bak /etc/fstab && echo "tmpfs	/dev/shm	tmpfs	defaults,rw,nosuid,nodev,noexec,relatime		0 0" >> /etc/fstab)

# setting kernel parameters

if [[ ! -s /etc/sysctl.d/hardening.conf ]]; then
	msg "Adding kernel parameters to /etc/sysctl.d/hardening.conf"
	cat >> /etc/sysctl.d/hardening.conf << EOF
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.ip_forward=0
net.ipv4.route.flush=1
net.ipv6.route.flush=1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF
sysctl -p
fi

### Enable IPV6 for Loopback interface
echo "net.ipv6.conf.lo.disable_ipv6 = 0" > /etc/sysctl.d/lo-ipv6.conf
sysctl -p  /etc/sysctl.d/lo-ipv6.conf

# authentication and accounting configuration

msg "Setting password quality parameters" && bak /etc/security/pwquality.conf && authconfig --passminlen=14 --enablerequpper --enablereqother --enablereqlower --enablereqdigit --update
grep -E "PASS_MAX_DAYS\s+365$" /etc/login.defs > /dev/null 2>&1 || (msg "Setting maximum number of days between password change at /etc/login.defs" && bak /etc/login.defs && perl -i -pe 's/(PASS_MAX_DAYS\s+)\d+/${1}365/' /etc/login.defs)
grep -E "PASS_MIN_DAYS\s+1$" /etc/login.defs > /dev/null 2>&1 || (msg "Setting minimum number of days between password change at /etc/login.defs" && bak /etc/login.defs && perl -i -pe 's/(PASS_MIN_DAYS\s+)\d+/${1}1/' /etc/login.defs)
[[ $(useradd -D | grep INACTIVE | cut -d '=' -f 2) -ne 30 ]] && msg "Setting day limit for inactive password lock" && useradd -D -f 30
for g in usops sysops oncall appops thdba dev bi; do
	if grep -w $g /etc/group > /dev/null 2>&1; then
		for u in $(lid -gn $g); do
			[[ $(chage -l $u | grep 'Password expires' | awk '{print $4}') == 'never' ]] && msg "Setting password expiry day limit for user $u" && chage --maxdays 365 $u
			[[ $(chage -l $u | grep 'Minimum number of days between password change' | perl -lane 'print $F[-1]') == 0 ]] && msg "Setting password change interval for user $u" && chage --mindays 365 $u
			[[ $(grep -w $u /etc/shadow | cut -d ':' -f 7) -ne 30 ]] && msg "Setting inactive password lock day limit for user $u"  && chage --inactive 30 $u
		done
	fi
done
for d in $(cat /etc/shadow | cut -d ':' -f 3); do
	[[ $d -gt $(($(date +%s) / 86400)) ]] && msg "Following users have date of last password change in future:" && grep $d /etc/shadow | cut -d ':' -f 1,3 && echo "Warning: Users with 'last password change date' in future found. Check the log."
done
grep -vP "^(console|tty\d+)$" /etc/securetty > /dev/null 2>&1 && msg "Restricting root login to ttys only" && bak /etc/securetty && perl -i -ne 'print if /^(console|tty\d+)$/' /etc/securetty

for pamconf in /etc/pam.d/{system-auth,password-auth}; do
  if ! grep -E  "\sdeny=" $pamconf > /dev/null 2>&1; then
    msg "Configuring lockout for failed password attempts and password reuse limit."
    bak $pamconf
    perl -i -pe 's/(auth        required      pam_env.so)/$1\nauth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900/;s/(auth        sufficient    pam_unix.so nullok try_first_pass)/$1\nauth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900/;s/(account     required      pam_unix.so)/account     required      pam_faillock.so\n$1/;s/(password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass) use_authtok/$1 remember=5 use_authtok/' $pamconf


elif grep -E  'auth        required      pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900' $pamconf > /dev/null 2>&1; then
  msg "Configuring lockout for failed password attempts and password reuse limit."
  bak $pamconf
  perl -i -pe 's/(auth        required      pam_faillock.so preauth silent) deny=5 unlock_time=1800 fail_interval=900/$1 audit deny=5 unlock_time=900/;s/(auth        \[default=die\] pam_faillock.so authfail deny=5 unlock_time=)1800 (fail_interval=900)/$1\900 $2/;s/(auth        required      pam_faillock.so authfail deny=5 unlock_time=)1800 (fail_interval=900)/$1\900 $2/;s/(password    sufficient    pam_unix.so sha512 shadow try_first_pass) use_authtok/$1 remember=5 use_authtok/' $pamconf
fi
done

# sudoers

if [[ ! -s /etc/sudoers.d/cis-hardening-sudoers ]] ; then
	msg "Adding entries to /etc/sudoers.d/cis-hardening-sudoers"
	cat >> /etc/sudoers.d/cis-hardening-sudoers << 'EOF'
Defaults use_pty
Defaults logfile=/var/log/sudo.log
EOF
fi

# sudoers
if [[ ! -s /etc/sudoers.d/hardening-sudoers ]] ; then
	msg "Adding entries to /etc/sudoers.d/hardening-sudoers"
	cat >> /etc/sudoers.d/hardening-sudoers << 'EOF'
Defaults use_pty
Defaults logfile=/var/log/sudo.log
EOF
fi

# setting hard limits for coredump
#
#if [[ ! -s /etc/security/limits.d/hardening-limits.conf ]]; then
#	msg "Adding entries to /etc/security/limits.d/hardening-limits.conf"
#	echo '*		hard	core	0' >> /etc/security/limits.d/hardening-limits.conf
#fi

# setting chronyd user

grep 'OPTIONS="-u chrony"' /etc/sysconfig/chronyd > /dev/null 2>&1 || (msg "Setting user for chronyd" && bak /etc/sysconfig/chronyd && perl -i -pe 's/OPTIONS.*/\# For CIS hardening\nOPTIONS=\"-u chrony\"/' /etc/sysconfig/chronyd && systemctl restart chronyd)

# rsyslog config

[[ -s /etc/rsyslog.d/hardening.conf ]] || (msg "Adding entries to /etc/rsyslog.d/hardening.conf" && echo '$FileCreateMode 0600' >> /etc/rsyslog.d/hardening.conf && systemctl restart rsyslog)

# journald logs to rsyslog

if ! (grep -Ev "^(#|$|\[Journal\]$)" /etc/systemd/journald.conf > /dev/null 2>&1); then
	msg "Adding entries to /etc/systemd/journald.conf"
	bak /etc/systemd/journald.conf
	cat >> /etc/systemd/journald.conf << EOF

# For CIS hardening
ForwardToSyslog=yes
Compress=yes
Storage=persistent
EOF
fi

# sshd config

if ! (grep 'CIS hardening changes' /etc/ssh/sshd_config > /dev/null 2>&1); then
	msg "Adding entries to /etc/ssh/sshd_config"
	bak /etc/ssh/sshd_config
	cat >> /etc/ssh/sshd_config << 'EOF'
# CIS hardening changes
LogLevel INFO
ClientAliveInterval 900
ClientAliveCountMax 0
LoginGraceTime 60
MaxStartups 10:30:60
MaxAuthTries 4
MaxSessions 10
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
GSSAPICleanupCredentials no
EOF
fi

# BASH profile changes

if [[ ! -s /etc/profile.d/hardening.sh ]]; then 
	msg "Adding entries to /etc/profile.d/hardening.sh"
	cat >> /etc/profile.d/hardening.sh << 'EOF'
readonly TMOUT=900
export TMOUT
EOF
fi

if [[ ! -s /etc/profile.d/set-umask.sh ]]; then
	msg "Adding entries to /etc/profile.d/set-umask.sh"
	cat >> /etc/profile.d/set-umask.sh << 'EOF'
umask 027
EOF
fi

# Removing file MOTD (Message Of The Day) /etc/motd
if [[ -f /etc/motd ]]; then
	msg "Message Of The Day file present. Removing the file"
	rm -rf /etc/motd
fi

# Updating crypto-policies
cp -p /etc/crypto-policies/back-ends/opensshserver.config /etc/crypto-policies/back-ends/opensshserver.config.$(date +%F).BAK

if [[ ! -s /etc/crypto-policies/policies/modules/TERRAPIN.pmod ]]; then 
	msg "Adding entries to /etc/crypto-policies/policies/modules/TERRAPIN.pmod"
	cat >> /etc/crypto-policies/policies/modules/TERRAPIN.pmod << 'EOF'
cipher@ssh = -CHACHA20*
ssh_etm = 0
EOF
fi

if [[ ! -s /etc/crypto-policies/policies/modules/NOCBC.pmod ]]; then 
	msg "Adding entries to /etc/crypto-policies/policies/modules/NOCBC.pmod"
	cat >> /etc/crypto-policies/policies/modules/NOCBC.pmod << 'EOF'
cipher@ssh = -*-CBC
EOF
fi

if [ -f "/etc/crypto-policies/back-ends/opensshserver.config" ]; then
	if grep -q "diffie-hellman-group-exchange-sha1," "/etc/crypto-policies/back-ends/opensshserver.config"; then
		msg "Removing "diffie-hellman-group-exchange-sha1," entry from /etc/crypto-policies/back-ends/opensshserver.config"
		sed -i "s/diffie-hellman-group-exchange-sha1,//g" "/etc/crypto-policies/back-ends/opensshserver.config"
	fi
fi

### Disable SHA1 crypto-policies
bash -c "cat > /etc/crypto-policies/policies/modules/NOSHA1.pmod" <<EOF
hash = -SHA1
sign = -*-SHA1
sha1_in_certs = 0
EOF

### Update crypto-policies
update-crypto-policies --set DEFAULT:NOCBC:NOSHA1:TERRAPIN

# Masking rsyncd
[[ $(systemctl is-enabled rsyncd | grep masked) ]] || (msg "Masking rsyncd" && systemctl mask rsyncd > /dev/null 2>&1)

## Setting permissions on /etc/*cron* files/directories
echo "Removing permissions for Group members and others"
for i in $(ls -l /etc/|grep cron|awk {'print $9'}); do chmod -R og-rwx "/etc/$i"; done
if [ $? -eq 0 ]
  then echo "$i: Done"
else
  echo "Could not harden /etc/*cron* files/directories"
fi

## Set umask explicitly to 027
msg "Setting umask explicitly to 027"
for file in /etc/{bashrc,profile,login.defs}; do
    bak $file
    sed -i 's/002/027/g; s/022/027/g' "$file"
    #sed -i '/^if \[ $UID -gt 199 \] && \[ "`\/usr\/bin\/id -gn`" = "`\/usr\/bin\/id -un`" \]; then$/,/^fi$/s/.*/umask 027/' "$file"
	if [ $?==0 ]
	then msg "$file: Done"
	else msg "Could not update umask in the files: $file"
	fi

done

## Update permissions and ownership on files in /var/log
## Following lines (264 - 374) are from OL8 cis hardening scan report and is integrated with OL8 cis hardening script

msg "Updating permissions and ownership on files in /var/log"
{
  l_op2='' l_output2=''
  l_uidmin="$(awk '/^s*UID_MIN/{print $2}' /etc/login.defs)"
  file_test_fix()
  {
      l_op2=''
      l_fuser='root'
      l_fgroup='root'
      if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then
        l_op2="$l_op2
  - Mode: $l_mode should be $maxperm or more restrictive
   - Removing excess permissions"
        chmod "$l_rperms" "$l_fname"
      fi
      if [[ ! "$l_user" =~ $l_auser ]]; then
        l_op2="$l_op2
  - Owned by: $l_user and should be owned by ${l_auser//|/ or }
   - Changing ownership to: $l_fuser"
        chown "$l_fuser" "$l_fname"
      fi
      if [[ ! "$l_group" =~ $l_agroup ]]; then
        l_op2="$l_op2
  - Group owned by: $l_group and should be group owned by ${l_agroup//|/ or }
   - Changing group ownership to: $l_fgroup"
        chgrp "$l_fgroup" "$l_fname"
      fi
      [ -n "$l_op2" ] && l_output2="$l_output2
 - File: $l_fname is:$l_op2
"
  }
  unset a_file && a_file=() # clear and initialize array
  # Loop to create array with stat of files that could possibly fail one of the audits
  while IFS= read -r -d $'\0' l_file; do
      [ -e "$l_file" ] && a_file+=("$(stat -Lc '%n^%#a^%U^%u^%G^%g' "$l_file")")
  done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)
  while IFS='^' read -r l_fname l_mode l_user l_uid l_group l_gid; do
      l_bname="$(basename "$l_fname")"
      case "$l_bname" in
        lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
            perm_mask='0113'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_rperms='ug-x,o-wx'
            l_auser='root'
            l_agroup='(root|utmp)'
            file_test_fix
            ;;
        secure | auth.log | syslog | messages)
            perm_mask='0137'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_rperms='u-x,g-wx,o-rwx'
            l_auser='(root|syslog)'
            l_agroup='(root|adm)'
            file_test_fix
            ;;
        SSSD | sssd)
            perm_mask='0117'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_rperms='ug-x,o-rwx'
            l_auser='(root|SSSD)'
            l_agroup='(root|SSSD)'
            file_test_fix
            ;;
        gdm | gdm3)
            perm_mask='0117'
            l_rperms='ug-x,o-rwx'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_auser='root'
            l_agroup='(root|gdm|gdm3)'
            file_test_fix
            ;;
        *.journal | *.journal~)
            perm_mask='0137'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_rperms='u-x,g-wx,o-rwx'
            l_auser='root'
            l_agroup='(root|systemd-journal)'
            file_test_fix
            ;;
        *)
            perm_mask='0137'
            maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
            l_rperms='u-x,g-wx,o-rwx'
            l_auser='(root|syslog)'
            l_agroup='(root|adm)'
            if [ "$l_uid" -lt "$l_uidmin" ] && [ -z "$(awk -v grp="$l_group" -F: '$1==grp {print $4}' /etc/group)" ]; then
              if [[ ! "$l_user" =~ $l_auser ]]; then
                  l_auser='(root|syslog|$l_user)'
              fi
              if [[ ! "$l_group" =~ $l_agroup ]]; then
                  l_tst=''
                  while l_out3='' read -r l_duid; do
                    [ "$l_duid" -ge "$l_uidmin" ] && l_tst=failed
                  done <<< "$(awk -F: '$4=='"$l_gid"' {print $3}' /etc/passwd)"
                  [ "$l_tst" != "failed" ] && l_agroup='(root|adm|$l_group)'
              fi
            fi
            file_test_fix
            ;;
      esac
  done < <(printf '%s\n' "${a_file[@]}")
  unset a_file # Clear array
  # If all files passed, then we report no changes
  if [ -z "$l_output2" ]; then
      echo -e '- All files in '/var/log/' have appropriate permissions and ownership
  - No changes required
'
  else
      # print report of changes
      echo -e "$l_output2"
  fi
}

echo "~~~~~~~~~~~~~~~~~~~~~~End - $(date +"%F %T")~~~~~~~~~~~~~~~~~~~~~~"