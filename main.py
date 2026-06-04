from __future__ import annotations

import argparse
import os
import shlex
import sys
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lab_core import CHECKERS, DEFAULT_TRACE, RULES, diagram_text, estimate_password_crack_time, run_check

WEB_ROOT = Path(__file__).resolve().parent / "webapp"

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_CYAN = "\033[38;5;51m"
ANSI_GREEN = "\033[38;5;84m"
ANSI_MAGENTA = "\033[38;5;213m"
ANSI_YELLOW = "\033[38;5;227m"
ANSI_BLUE = "\033[38;5;75m"
ANSI_RED = "\033[38;5;203m"

CLI_ART = [
    r"   ___        __                __        ______      __      __       __      ",
    r"  / _ | ___  / /____ ___  ___  / /  ___  / __/ /__   / /____ / /____  / /____  ",
    r" / __ |/ _ \/ __/ -_) _ \/ _ \/ _ \/ _ \/ _// / -_) / __/ -_) __/ _ \/ __/ -_) ",
    r"/_/ |_|\___/\__/\__/_//_/ .__/_.__/\___/_/ /_/\__/  \__/\__/_/  \___/\__/\__/  ",
    r"                       /_/                                                       ",
]


def colorize(text: str, color: str = "") -> str:
    if not sys.stdout.isatty() or not color:
        return text
    return f"{color}{text}{ANSI_RESET}"


class WebAppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self) -> None:
        # Disable aggressive caching during local development.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberDFA: web server and interactive CLI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to serve on.")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the browser automatically.",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Start the interactive CLI instead of the web server.",
    )
    parser.add_argument(
        "--command",
        help="Run a single CLI command and exit.",
    )
    return parser.parse_args()


def run_server(host: str, port: int, open_browser: bool) -> None:
    if not WEB_ROOT.exists():
        raise SystemExit(f"Web root not found: {WEB_ROOT}")

    server = ThreadingHTTPServer((host, port), WebAppHandler)
    url = f"http://{host}:{port}"

    print(f"Serving webapp from: {WEB_ROOT}")
    print(f"Open: {url}")
    print("Press Ctrl+C to stop.")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_banner() -> None:
    print(colorize(CLI_ART[0], ANSI_CYAN))
    print(colorize(CLI_ART[1], ANSI_MAGENTA))
    print(colorize(CLI_ART[2], ANSI_GREEN))
    print(colorize(CLI_ART[3], ANSI_YELLOW))
    print(colorize(CLI_ART[4], ANSI_BLUE))
    print()
    print(colorize("CyberDFA CLI", ANSI_BOLD + ANSI_CYAN))
    print(colorize("Slash commands: /help, /email, /phone, /password, /ipv4, /sqli, /xss, /diagram, /rules, /clear, /exit", ANSI_DIM + ANSI_GREEN))
    print(colorize("Type /web to see the local web UI URL.", ANSI_DIM + ANSI_MAGENTA))


def print_rules(rule_key: str) -> None:
    rule = RULES.get(rule_key)
    if not rule:
        print(f"Unknown rule set: {rule_key}")
        return

    print(rule["title"])
    print(rule["text"])


def print_diagram(kind: str) -> None:
    try:
        print(diagram_text(kind))
    except ValueError as exc:
        print(str(exc))


def print_result(kind: str, value: str) -> None:
    result = run_check(kind, value)
    print(f"[{kind}] input: {value}")
    print(f"status: {result.summary}")
    print("trace:")
    for line in result.trace or DEFAULT_TRACE:
        print(f"  {line}")

    if kind == "password":
        estimate_summary, estimate_details = estimate_password_crack_time(value)
        print(estimate_summary)
        for detail in estimate_details:
            print(f"  {detail}")


def show_help() -> None:
    print("Commands:")
    print("  /email <value>      Validate an email address")
    print("  /phone <value>      Validate a 10-digit phone number")
    print("  /password <value>   Validate a password and estimate crack time")
    print("  /ipv4 <value>       Validate an IPv4 address")
    print("  /sqli <value>       Detect SQL injection signatures")
    print("  /xss <value>        Detect XSS signatures")
    print("  /diagram <kind>     Show an ASCII DFA diagram for email, phone, or ipv4")
    print("  /rules <kind>       Show the rule summary for a checker")
    print("  /web                Print the web server URL")
    print("  /clear              Clear the terminal")
    print("  /exit, /quit        Leave the CLI")


def handle_command(raw_line: str) -> bool:
    line = raw_line.strip()
    if not line:
        return True

    if line.startswith("/"):
        line = line[1:]

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        print(f"Parse error: {exc}")
        return True

    if not parts:
        return True

    command = parts[0].lower()
    arguments = parts[1:]

    if command in {"exit", "quit"}:
        return False
    if command == "help":
        show_help()
        return True
    if command == "clear":
        clear_screen()
        return True
    if command == "web":
        print("Open the web UI with: python main.py")
        print("Default URL: http://127.0.0.1:8000")
        return True
    if command == "rules":
        if not arguments:
            print("Usage: /rules <email|phone|password|ipv4|sqli|xss>")
            return True
        print_rules(arguments[0].lower())
        return True
    if command == "diagram":
        if not arguments:
            print("Usage: /diagram <email|phone|ipv4>")
            return True
        print_diagram(arguments[0].lower())
        return True
    if command in CHECKERS:
        if not arguments:
            print(f"Usage: /{command} <value>")
            return True
        print_result(command, " ".join(arguments))
        return True

    print(f"Unknown command: {command}")
    print('Type "/help" for the command list.')
    return True


def run_cli(one_shot_command: str | None = None) -> None:
    clear_screen()
    print_banner()

    if one_shot_command is not None:
        handle_command(one_shot_command)
        return

    while True:
        try:
            raw_line = input("cyberdfa> ")
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print("\nExiting.")
            break

        if not handle_command(raw_line):
            break


def main() -> None:
    args = parse_args()
    if args.cli:
        run_cli(args.command)
    else:
        run_server(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
