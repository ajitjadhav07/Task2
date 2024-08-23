#!/bin/bash

# Function to log messages
log_message() {
    local message=$1
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${message}"
}

# User and Group Audits
audit_users() {
    log_message "Auditing users and groups..."
    echo "Listing all users and groups:"
    cut -d: -f1 /etc/passwd
    cut -d: -f1 /etc/group
    
    log_message "Checking for UID 0 users..."
    awk -F: '$3 == 0 {print $1}' /etc/passwd

    log_message "Checking users without passwords..."
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow

    log_message "Checking for weak passwords (using default example)..."
    # Add your weak password checks here
}

# File and Directory Permissions
audit_permissions() {
    log_message "Auditing file and directory permissions..."
    echo "World-writable files and directories:"
    find / -perm -0002 -type f -print
    find / -perm -0002 -type d -print

    echo "SUID and SGID files:"
    find / -perm -4000 -o -perm -2000 -type f -print

    echo "Checking .ssh directory permissions..."
    find / -type d -name ".ssh" -exec ls -ld {} \;
}

# Service Audits
audit_services() {
    log_message "Auditing services..."
    echo "Running services:"
    systemctl list-units --type=service --state=running

    echo "Checking for unauthorized services..."
    # Add your checks for unauthorized services here
}

# Firewall and Network Security
audit_firewall_network() {
    log_message "Auditing firewall and network configuration..."
    echo "Firewall status:"
    ufw status

    echo "Open ports and associated services:"
    netstat -tuln

    echo "Checking IP forwarding..."
    sysctl net.ipv4.ip_forward
}

# IP and Network Configuration Checks
check_ip_network() {
    log_message "Checking IP and network configuration..."
    echo "IP addresses assigned to the server:"
    ip addr show

    # Additional checks for public vs private IPs
    # This could include IP geolocation or a predefined list of private IP ranges
}

# Security Updates and Patching
check_updates() {
    log_message "Checking for security updates..."
    apt-get update -s | grep 'upgradable'
}

# Log Monitoring
check_logs() {
    log_message "Checking logs for suspicious entries..."
    grep 'Failed password' /var/log/auth.log
}

# Server Hardening
harden_server() {
    log_message "Hardening server..."

    echo "Configuring SSH..."
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd

    echo "Disabling IPv6..."
    # Update sysctl configuration to disable IPv6
    sed -i '/^net.ipv6.conf.all.disable_ipv6/s/^#//g' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    echo "Securing bootloader..."
    # Assuming GRUB is used
    grub-mkpasswd-pbkdf2
    # Update GRUB configuration with the password

    echo "Configuring firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable

    echo "Configuring automatic updates..."
    apt-get install -y unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Main Script Execution
log_message "Starting security audit and hardening..."

audit_users
audit_permissions
audit_services
audit_firewall_network
check_ip_network
check_updates
check_logs
harden_server

log_message "Security audit and hardening completed."
