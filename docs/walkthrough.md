# OBSIDIAN PROTOCOL — Operation Log
### Attack Chain: The Fall of TARGET-49

> **Format note:** this document is not a list of commands — it's a
> chronological operation log. At each stage you'll find three
> things: the **situation** (scenario), the **root cause analysis**
> (why it works), and the **operator's task** (a directive that
> points toward the solution without handing it over). This is not an
> answer sheet — if you get stuck, check the hint boxes, but you will
> write the exploit code yourself.

---

## Situation Briefing

**OPERATOR** is deployed against **TARGET-49** in the range. From the
outside it looks like an ordinary Apache install — but the version
banner stands out: **2.4.49**. Released in October 2021, it lived for
only a few weeks. Within that window, Apache's path normalization
logic had a serious regression.

TARGET-49's attack surface currently consists of a single thing:
**HTTP**. But from that one layer, with the right chain, the path
leads all the way to a root shell.

```
[RECON]  →  VECTOR-I [INITIAL ACCESS via path traversal → RCE]  →
[FOOTHOLD]  →  [LOCAL ENUMERATION]  →
VECTOR-II [PRIVILEGE ESCALATION via PwnKit]  →  [ROOT — OPERATION COMPLETE]
```

MITRE ATT&CK mapping:

| Stage | Tactic | Technique |
|---|---|---|
| Recon | Reconnaissance | T1595 (Active Scanning) |
| VECTOR-I | Initial Access | T1190 (Exploit Public-Facing Application) |
| VECTOR-I | Execution | T1059 (Command and Scripting Interpreter) |
| VECTOR-II | Privilege Escalation | T1548.001, T1068 |

---

## Stage 0: Bring Up the Range

```bash
./setup.sh
# or manually:
docker-compose up -d
docker exec -it obsidian-operator bash
```

From the OPERATOR box you can reach TARGET-49 over DNS — compose
automatically resolves the service name (`target-49`).

---

## Stage 1: Recon — "Is TARGET-49 Really That Vulnerable Version?"

**Situation:** the first rule is not to assume anything. Seeing
"Apache/2.4.49" in the banner is exciting, but a real operator (and
you) verifies it — the banner can be spoofed, or the target could be
on the vulnerable version while still not allowing the
**configuration** prerequisite to be triggered.

**Root cause context:** VECTOR-I isn't purely a version issue — it
also has a **configuration prerequisite**. As Apache's own advisory
specifically notes, this vulnerability can only be triggered on
systems that have moved away from the `Require all denied` default.

**Operator's task:**
- Confirm the Apache version from the HTTP headers or via `nmap -sV`
- Check whether the `/cgi-bin/` directory exists — an early signal of
  whether mod_cgi is active
- **Question:** why is it risky to trust the version banner alone and
  jump straight to attempting RCE?

---

## VECTOR-I — Stage 2: Initial Access (Path Traversal)

**Situation:** now it's time to trigger VECTOR-I. The goal is to test
whether Apache can be made to **read** files outside its
`DocumentRoot`. You'll prove this first against a harmless target (the
fake secrets file the range has planted).

**Root cause — this part is critical, don't skip it:** in Apache
2.4.49, the path normalization function was rewritten. The new code
decoded encoded characters in the URL **in a single pass**. `%2e` was
converted to `.`, producing `..`, which was then rejected. **But** if
you add one extra layer of encoding (something like `%%32%65`), the
normalization function performed the traversal check **before**
decoding it. The actual decode happened **after** the check passed —
the check was looking at a `../` sequence that didn't exist yet.

This is why **CISA's official note matters**: the original
CVE-2021-41773 patch only fixed single-level encoding. Because
Apache's first fix proved insufficient, CISA had to open a second CVE
number (CVE-2021-42013).

**Operator's task:**
- Through a path that matches a `ScriptAlias` (`/cgi-bin/...`), attempt
  traversal using encoded `../` sequences
- Try single-encoding first; if that fails, try **double-encoding** —
  this is how you'll personally observe the CVE-2021-41773 vs 42013
  distinction
- **Verification:** if you can see the contents of
  `/opt/internal/secrets.env` in the HTTP response, the first stage of
  VECTOR-I has succeeded

> **Hint box:** try combining the `/cgi-bin/` prefix + encoded
> traversal + target file path. Using the ScriptAlias path is
> mandatory.

---

## VECTOR-I — Stage 3: Execution (From Reading to Running Commands)

**Situation:** you can read files. The question now is: **how do you
turn this read capability into command execution?**

**Root cause:** with mod_cgi active, Apache interprets requests to
certain paths as "this is a CGI script, execute it." If you use
traversal to point that path at an interpreter that already exists on
the system (such as `/bin/sh`), and send the request body as "input
to this script," Apache **feeds that body to the shell as a
command.**

**Operator's task:**
- Using a POST request, point the traversal path at a shell
  interpreter and try running a harmless command (`id`, `whoami`) via
  the body
- **Critical question:** which user does this command run as? Go back
  to the Dockerfile — which user does Apache run under on TARGET-49?

> **Hint box:** you need to set the Content-Type header so CGI
> interprets the request as a script invocation, and supply your
> command (`echo; id`) in the body.

---

## Stage 4: Foothold — Stabilizing the Shell

**Situation:** RCE has been achieved (VECTOR-I is complete), but
sending every command as a one-off HTTP request is both slow and
fragile. This is where you move to an **interactive shell**.

**Operator's task:**
- Open a listener on the OPERATOR box (a reverse shell scenario — since
  the range is isolated, the connection stays entirely within
  `obsidian-range`)
- Through the RCE, trigger a reverse shell from TARGET-49 back to that
  listener
- Stabilize the shell

**Verification:** running `id` should show `labuser`.

---

## Stage 5: Local Enumeration

**Situation:** you have a shell as `labuser`, but that's not enough.
This is where systematic enumeration happens: SUID binaries, sudo
permissions, installed packages.

**Operator's task:**
- Confirm the SUID bit with `ls -la /usr/bin/pkexec` (`-rwsr-xr-x`)
- Confirm the version with `dpkg -l | grep policykit`

---

## VECTOR-II — Stage 6: Privilege Escalation (The Anatomy of PwnKit)

**Situation:** this is the most instructive part of the operation,
because PwnKit is **not a buffer overflow** — it's a **logic error**.

**Root cause — in detail:**

`pkexec`, in normal use, is always invoked with at least one
argument. Its C code processed arguments in a loop starting from
`argv[1]` — `argv[0]` was skipped, under the reasonable-looking
assumption that "argc is always at least 1."

But if you invoke the `execve()` syscall **directly**, leaving the
argv array completely empty (`argc=0`), that assumption breaks.
`pkexec` then tries to read a nonexistent `argv[1]` and reads past the
end of allocated memory — an **out-of-bounds read/write**. The memory
it reads past the boundary into happens to be the process's
**environment variable** array.

This is where `GCONV_PATH` comes in: when performing character-set
conversion, glibc looks at the directories listed in the
`GCONV_PATH` variable to load an appropriate "gconv module" (a `.so`
file). If you supply an invalid `CHARSET` value, glibc starts
searching for a module to perform that conversion — and if you point
`GCONV_PATH` at a directory you control, you can make it load
**your own `.so` file**, with root privileges.

**The reason this is so powerful:** this code path executes
**before** pkexec's normal authorization check. The exploit never
enters the authentication logic at all — which makes it both
trivially exploitable and (as you'll see in the WARDEN module)
**invisible** in auth logs.

**Operator's task:**
- Write a C program that invokes `execve()` with an empty argv array
- Prepare a fake `gconv-modules` file and a `.so` file that presents
  itself as a "module" — inside that `.so`, the `gconv_init()`
  function (which will run with root privileges) should call
  `setuid(0)` and spawn a shell

> **Hint box:** Qualys's original technical advisory (2022-01-25)
> walks through every step of this chain. Key terms: `GCONV_PATH`, the
> `gconv-modules` file format, the `CHARSET` environment variable.

**Verification:** before the exploit, `id` → `uid=1000(labuser)`.
After the exploit, `id` → `uid=0(root)`. **OPERATION COMPLETE.**

---

## Stage 7: Evidence Collection and Timeline

While filling in the `reports/exploitation-evidence.md` template,
don't forget the timestamps — they are the single most important
piece of evidence in the operation report.

---

## Looking Back: Why Is This Chain "Realistic"?

The combination of VECTOR-I + VECTOR-II mirrors the standard
real-world attack structure: get in from the external surface via
RCE, then expand through local privilege escalation. For real
campaign data (including the AndroxGh0st botnet), go to
`docs/threat-intelligence.md`. To see how this attack gets caught,
see `detection/README.md` (the WARDEN module).
