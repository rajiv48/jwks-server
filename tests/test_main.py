import runpy
from unittest import mock


def test_main_serves_on_port_8080():
    with mock.patch("uvicorn.run") as run:
        runpy.run_module("jwks_server", run_name="__main__")

    run.assert_called_once()
    assert run.call_args.kwargs["port"] == 8080
