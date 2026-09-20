# JWKS Server

A small RESTful JWKS server (Python 3.11+, FastAPI + Uvicorn) that:

- generates RSA-2048 key pairs, each with a unique `kid` and an expiry time;
- publishes only **unexpired** public keys at `GET /.well-known/jwks.json`;
- issues RS256-signed JWTs at `POST /auth` (authentication is mocked — no body or credentials are checked);
- signs with an **expired** key, and an already-expired `exp`, when the `expired` query parameter is present.



## Endpoints

| Method | Path                     | Behaviour                                                                 |
|--------|--------------------------|---------------------------------------------------------------------------|
| GET    | `/.well-known/jwks.json` | `{"keys": [...]}` containing only keys whose expiry is in the future.     |
| POST   | `/auth`                  | Returns a signed JWT (`text/plain`) using the current unexpired key.      |
| POST   | `/auth?expired`          | Same, but signed with the expired key; `exp` is in the past.              |

Any other method on these paths returns `405`; unknown paths return `404`.
The `kid` is placed in every JWT header so verifiers can pick the matching JWK.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m jwks_server                # listens on http://0.0.0.0:8080
```

Try it:

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Tests, coverage, lint

```bash
pip install -r requirements-dev.txt
pytest                # runs the suite; fails if coverage drops below 80%
ruff check .          # lint
ruff format --check . # formatting
```

## Black-box test client

Download the client for your OS from <https://github.com/jh125486/CSCE3550/releases>, start
nothing manually (it launches the server itself), and run from the client's folder:

```bash
./gradebot project-1 --dir /path/to/jwks-server --run "python -m jwks_server"
```

If you use a virtualenv, point `--run` at it, e.g. `--run ".venv/bin/python -m jwks_server"`.

## Layout

```
jwks_server/
  keys.py       RSA generation, KeyRecord (kid + expiry + JWK export), thread-safe KeyStore
  app.py        FastAPI app: JWKS + /auth handlers, JWT issuing
  __main__.py   `python -m jwks_server` entry point (port 8080)
tests/          pytest suite (fake clock for deterministic expiry/rotation tests)
```

## Design notes

- **Key lifecycle.** At start-up the store creates one valid key (1 hour) and one key that
  expired 1 hour ago. If the valid key expires while the server is running, a new key is generated
  on demand, so `/auth` and the JWKS never go empty.
- **Token lifetime.** Normal tokens last 30 minutes but never outlive their signing key.
- **`expired` parameter.** Presence is what matters (`?expired`, `?expired=true`, `?expired=false`
  all trigger it), matching "if the query parameter is present".
- **Time is injectable.** `KeyStore(clock=...)` lets tests move time forward instead of sleeping.
