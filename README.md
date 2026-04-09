# CyberSecLab VIT

A lightweight interactive web lab for finite automata validation and basic cybersecurity pattern checks.

Live demo: https://cyberseclab-vit.vercel.app

## What this project does

CyberSecLab combines automata-style validators and security detectors in one interface:

- Email validation with DFA-style state transitions
- Phone validation (10-digit DFA flow)
- Password validation with estimated brute-force crack time
- IPv4 validation with octet rules
- SQL injection signature detection
- XSS signature detection
- Dedicated DFA visualization area with fullscreen-on-click support

## Features

- Fast client-side checks in plain JavaScript
- Rule popups for each checker
- Status badge plus detailed evaluation log
- Dedicated lower diagram panel for DFA rendering
- Retro cyber UI theme
- No framework dependency in frontend
- Simple Python static server for local development

## Tech stack

- Frontend: HTML, CSS, Vanilla JavaScript
- Local server: Python standard library (`http.server`)
- Hosting: Vercel

## Project structure

- main.py: local server entrypoint
- webapp/index.html: app layout and UI markup
- webapp/styles.css: all styling and layout behavior
- webapp/app.js: checker logic, DFA rendering, interaction flow

## Run locally

Requirements:

- Python 3.10+

Start the app:

1. Open a terminal in the project root.
2. Run:

   python main.py

3. Open the local URL shown in terminal (default: http://127.0.0.1:8000).

Optional flags:

- python main.py --port 8188
- python main.py --host 0.0.0.0
- python main.py --no-browser

## How to use

1. Enter input in the text box.
2. Run any checker from the control panel.
3. Read pass/fail status and details in the output panel.
4. Open Email, Phone, or IPv4 DFA from the diagram buttons.
5. Click on the rendered DFA image to open it in fullscreen.

## Deployment

Deployed on Vercel at:

- https://cyberseclab-vit.vercel.app

## Notes

- The tool is for educational and demo purposes.
- Security detections are signature-based heuristics, not full static or dynamic analysis.

## Author

Built and iterated as part of a TOC plus cybersecurity visualization project.
