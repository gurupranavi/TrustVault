'''Compatibility shim for test imports.

The test suite expects a top‑level module named ``app`` that provides the Flask
application object and utility functions such as ``init_db``, ``db``, ``run``,
``one`` and ``now``. In the project layout these symbols live inside the
``TrustVault/app`` package (``TrustVault/app/__init__.py``).  Adding this small
shim module allows ``import app`` to resolve correctly without altering the
existing package structure.
'''

# Re‑export everything from the actual package
from TrustVault.app import *  # noqa: F401,F403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

