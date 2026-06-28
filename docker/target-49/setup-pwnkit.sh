#!/bin/bash
# ============================================================
# setup-pwnkit.sh — OBSIDIAN PROTOCOL / VECTOR-II
#
# This script installs the polkit/pkexec package carrying the
# PwnKit (CVE-2021-4034) vulnerability inside the container.
#
# What CVE-2021-4034 is (short technical summary):
#   pkexec used argv[0] (the name the process was invoked under)
#   without any validation. When invoked with argc=0 (i.e. with no
#   arguments at all), pkexec would read past the end of its own
#   argv array and start consuming data from the environment
#   instead. This allowed arbitrary shared library injection (with
#   root privileges) via environment variables such as GCONV_PATH.
#
# Affected versions: polkit 0.105 - 0.120 (including the default
# version shipped in Debian bullseye).
#
# This script deliberately leaves an UNPATCHED polkit version
# installed.
# ============================================================
set -e

echo "[*] Preparing the PwnKit (CVE-2021-4034) lab environment..."

apt-get update
apt-get install -y policykit-1=0.105-31  # bullseye's default, vulnerable version

# Verify the pkexec binary carries the SUID bit
# (this is the prerequisite for CVE-2021-4034)
ls -la /usr/bin/pkexec

echo "[*] Setup complete. pkexec is installed with the SUID bit set."
echo "[*] Vulnerable version: $(dpkg -l | grep policykit-1)"
