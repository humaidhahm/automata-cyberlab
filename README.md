# Automata Cyberlab

A neon-styled automata and security lab for validating inputs, visualizing DFA flows, and testing simple attack-pattern heuristics.

[![Live Demo](https://img.shields.io/badge/demo-online-00d4ff?style=for-the-badge&logo=vercel&logoColor=white)](https://cyberseclab-vit.vercel.app)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/CLI-slash%20commands-8b5cf6?style=for-the-badge&logo=windowsterminal&logoColor=white)](#cli)
[![Web UI](https://img.shields.io/badge/web%20ui-visual%20lab-f43f5e?style=for-the-badge&logo=googlechrome&logoColor=white)](#web-app)

> Local web app + CLI, sharing the same validation core.

```text
    ___         __                      __  __      __
   / _ | ___   / /____ ___  ___  ___   / /_/ /__   / /__
  / __ |/ _ \ / __/ -_) _ \/ _ \/ _ \ / __/ / -_) /  '_/
 /_/ |_|\___/ \__/\__/_//_/\___/_//_/ \__/_/\__/ /_/\_\

  finite automata + security checks + terminal workflow
```

## Snapshot

| Area | What it gives you |
| --- | --- |
| Web UI | A colorful browser workspace for running checks and viewing DFA diagrams |
| CLI | Slash-command terminal mode with the same validation logic |
| Core logic | Shared Python rules for email, phone, password, IPv4, SQLi, and XSS |
| Diagrams | Built-in DFA views for the automata-based validators |

<details>
<summary>What makes this different</summary>

- The browser UI and terminal CLI use the same validator engine.
- The README is structured like a compact project landing page instead of a plain checklist.
- The interface focuses on DFA visualization, signature detection, and terminal-first workflows.

</details>

## What it checks

| Checker | Behavior | Visual cue |
| --- | --- | --- |
| Email | DFA-style validation with local part, `@`, domain, and TLD transitions | `q0 → q5` |
| Phone | Exactly 10 digits, one transition per digit | `q0 → q10` |
| Password | Length, uppercase, lowercase, digit checks, plus estimated brute-force crack time | entropy score |
| IPv4 | Four octets, numeric-only, `0-255`, no leading zeros | dotted octets |
| SQL injection | Signature-based heuristics and quote-balance hints | alert traces |
| XSS | URL-decoded payload scanning for common script indicators | decoded payload |

## Highlights

- Fast client-side checks in plain JavaScript
- Shared Python validation core for the CLI
- Inline rule popups for each checker
- Status badge plus evaluation trace
- DFA diagram panel with fullscreen support
- Retro cyber UI with a more colorful terminal-inspired presentation
- No frontend framework dependency
- Clean split between presentation, logic, and server entrypoints
- Easy terminal workflow for quick checks and demo runs

## Interface notes

The project deliberately mixes several UI patterns so it reads more like a real tool than a single-purpose demo:

1. A top-level hero with neon branding
2. Compact summary tables for fast scanning
3. A details disclosure block for deeper context
4. Code fences for copy-friendly startup commands
5. A fixed project tree to clarify the structure

## Project layout

```text
.
├── main.py          # local server + CLI entrypoint
├── lab_core.py      # shared validation logic
├── webapp/
│   ├── index.html   # interface markup
│   ├── styles.css   # visual design
│   └── app.js       # browser-side logic and DFA rendering
```

## Run locally

Requirements:

- Python 3.10+

### Web app

```bash
python main.py
```

Then open the URL printed in the terminal, usually `http://127.0.0.1:8000`.

Optional flags:

```bash
python main.py --port 8188
python main.py --host 0.0.0.0
python main.py --no-browser
```

### CLI

```bash
python main.py --cli
```

The CLI supports slash commands, a persistent prompt, and colorized terminal branding.

```bash
/help
/rules password
/diagram email
```

CLI examples:

```bash
/help
/email abc@mail.com
/phone 1234567890
/password StrongPass1
/ipv4 192.168.1.10
/sqli ' OR 1=1 --
/xss <script>alert(1)</script>
/diagram email
/rules password
```

## Usage flow

1. Enter input in the text box or the CLI prompt.
2. Run a checker from the control panel or by slash command.
3. Read the pass/fail summary and evaluation trace.
4. Open Email, Phone, or IPv4 DFA diagrams when you want the automata view.
5. Click a rendered DFA to expand it fullscreen.

## Badges And Signals

These badges are intentionally loud so the README feels more like a landing page and less like a plain text file.

| Signal | Meaning |
| --- | --- |
| Demo badge | Points to the deployed experience |
| Python badge | Shows the runtime requirement |
| CLI badge | Highlights the terminal mode |
| Web UI badge | Highlights the browser workflow |

## Deployment

The project is deployed on Vercel:

- https://cyberseclab-vit.vercel.app

## Notes

- The tool is for educational and demo purposes.
- Security detections are signature-based heuristics, not full static or dynamic analysis.
- The CLI and web app share the same core validation rules.

