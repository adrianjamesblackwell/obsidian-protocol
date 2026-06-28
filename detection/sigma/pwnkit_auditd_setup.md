# Required auditd Rule

This file describes the **mandatory prerequisite** for producing the
data source the `pwnkit_cve_2021_4034.yml` Sigma rule depends on.

Add the following to `/etc/audit/rules.d/pwnkit.rules`:

```
-w /usr/bin/pkexec -p x -k pkexec_exec
```

Without this rule, `auditd` never logs `pkexec` executions, and the
`selection_auditd_primary` / `selection_auditd_env` conditions in the
Sigma rule will never fire — meaning the rule itself can be perfectly
correct while staying silent simply because its data source (the
auditd log) was never produced.

For detailed setup steps, see: [`detection/README.md`](../README.md#detection-setup-pwnkit-via-auditd)
