"""Entry point: ``python -m jwks_server`` serves HTTP on port 8080."""

import uvicorn

from jwks_server.app import create_app

HOST = "0.0.0.0"  # noqa: S104 - the server must be reachable from the test client
PORT = 8080


def main() -> None:
    """Start the HTTP server."""
    uvicorn.run(create_app(), host=HOST, port=PORT)


if __name__ == "__main__":
    main()
