"""Fall Risk Trustfall — local artifact verifier."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("fallrisk-trustfall")
except PackageNotFoundError:
    # Package is not installed (e.g. running from source tree without install).
    # This sentinel makes the failure mode obvious without breaking imports.
    __version__ = "0.0.0+unknown"
