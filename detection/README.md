# WARDEN MODULE — Detection Engineering
### OBSIDIAN PROTOCOL / How This Attack Chain Gets Caught

This folder contains **real, executable detection rules** for VECTOR-I
and VECTOR-II. The goal isn't just "how did I attack" — it's
answering "how would a SOC analyst actually see this."

## Why There Are Two Different Detection Strategies

| CVE | Log Source | Reliability | Why |
|---|---|---|---|
| CVE-2021-41773/42013 | Apache access log | High | The request happens at the HTTP level, so it's always logged |
| CVE-2021-4034 (PwnKit) | **auditd (syscall)**, NOT auth.log | auth.log: Low / auditd: High | The exploit runs **ahead of** pkexec's authentication+logging code |

The PwnKit part is a particularly important lesson: most people
assume "I'll check auth.log, I'll see it if pkexec ran." **That's
wrong.** The vulnerability is triggered before pkexec ever enters its
normal authentication/logging flow. That's why
`detection/sigma/pwnkit_cve_2021_4034.yml` uses the auditd syscall
level as its primary signal, and treats auth.log as a "bonus if
present" signal at best.

## Detection Setup: PwnKit via auditd

To test this detection against the range's `target-49` service
(container: `obsidian-target-49`):

```bash
docker exec -it obsidian-target-49 bash
apt-get install -y auditd audispd-plugins
echo "-w /usr/bin/pkexec -p x -k pkexec_exec" >> /etc/audit/rules.d/pwnkit.rules
service auditd restart
```

After running the PwnKit exploit:
```bash
ausearch -k pkexec_exec | grep GCONV_PATH
```

This command shows how the root shell obtained in Stage 5 of the
walkthrough actually appears inside auditd.

## Testing the Sigma Rules

The rules are written in standard Sigma format and can be imported
into the [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) or any
Sigma-compatible SIEM (Splunk, Elastic, Wazuh):

```bash
pip install sigma-cli --break-system-packages
sigma convert -t splunk detection/sigma/apache_path_traversal_cve_2021_41773.yml
```

## YARA Rules

`detection/yara/pwnkit_artifacts.yar` scans for artifacts the PwnKit
exploit leaves on disk (a forged `.so` file, a fake `gconv-modules`
file). Test it after running the exploit in the lab:

```bash
yara detection/yara/pwnkit_artifacts.yar /tmp/ -r
```

## Patch / Permanent Remediation

| CVE | Permanent Fix |
|---|---|
| CVE-2021-41773/42013 | Upgrade Apache to **2.4.51+**. Interim mitigation: keep the `Require all denied` default, disable unnecessary `Alias`/`ScriptAlias` directories |
| CVE-2021-4034 | `apt-get update && apt-get install policykit-1` (patched version). Emergency interim mitigation: `chmod 0755 /usr/bin/pkexec` (removes the SUID bit — makes pkexec unusable but closes the vulnerability) |

## MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Discovery | File and Directory Discovery | T1083 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Setuid/Setgid | T1548.001 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
