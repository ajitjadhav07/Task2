# Security Audit and Hardening Script

This script automates the security audit and hardening process for Linux servers. It performs checks on user accounts, file permissions, services, firewall settings, and more. It also applies hardening measures to improve server security.

## Prerequisites

- Linux server
- Root or sudo access
- Git

## Usage

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/security_audit_hardening.git
   cd security_audit_hardening
   ```

2. **Make the Script Executable:**

   ```bash
   chmod +x scripts/audit_and_harden.sh
   ```

3. **Run the Script:**

   ```bash
   sudo ./scripts/audit_and_harden.sh
   ```

## Script Overview

- `audit_users`: Checks user accounts and passwords.
- `audit_permissions`: Scans file and directory permissions.
- `audit_services`: Lists and checks running services.
- `audit_firewall_network`: Audits firewall and network configurations.
- `check_ip_network`: Checks IP configurations and public vs private IPs.
- `check_updates`: Checks for available security updates.
- `check_logs`: Monitors logs for suspicious activities.
- `harden_server`: Applies hardening measures including SSH configuration, firewall settings, and more.

## Customization

You can extend the script with custom checks by editing the functions or adding new ones. Customize settings in the script as needed for your environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
