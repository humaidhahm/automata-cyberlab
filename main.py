from __future__ import annotations

import argparse
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent / "webapp"


class WebAppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self) -> None:
        # Disable aggressive caching during local development.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve the Finite State webapp locally.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to serve on.")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the browser automatically.",
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


def main() -> None:
    args = parse_args()
    run_server(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
