"""Shared helpers for the test suite.

Hashing the administrator password is deliberately expensive: the
``PBKDF2_ITERATIONS`` cost in :mod:`pbp_monitoring.config_store` is what
protects the stored password. Every test that completes the admin setup and
signs in pays that cost several times over, which dominates the runtime of the
suite without proving anything the cost itself does not already state.

The modules that exercise sign-in lower the cost for their own duration.
``SHIPPED_PBKDF2_ITERATIONS`` records the real value at import time, before any
patch is active, so a test can still prove the shipped default is strong.

Lowering the cost is safe for stored data: ``verify_admin_password`` reads the
iteration count back from the ``admin_auth`` row, so a database written with the
production cost keeps verifying at that cost.
"""

from unittest.mock import patch

from pbp_monitoring import config_store

SHIPPED_PBKDF2_ITERATIONS = config_store.PBKDF2_ITERATIONS
TEST_PBKDF2_ITERATIONS = 1_000

_patchers = []


def start_fast_password_hashing() -> None:
    """Lower the password hashing cost for the calling test module."""
    patcher = patch.object(config_store, "PBKDF2_ITERATIONS", TEST_PBKDF2_ITERATIONS)
    patcher.start()
    _patchers.append(patcher)


def stop_fast_password_hashing() -> None:
    """Restore the shipped password hashing cost."""
    _patchers.pop().stop()


# `BaseServer.shutdown()` only returns once the serving loop notices the stop
# flag, which it checks every `poll_interval` seconds. The 0.5 s default made
# every test that starts an HTTP or HTTPS server wait half a second on teardown.
SERVER_POLL_INTERVAL = 0.01
