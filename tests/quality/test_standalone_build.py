"""Native recipes preserve original notices and bind every build input."""

import base64
import hashlib
from pathlib import Path

import pytest

from scripts.build_standalone import analysis_binaries, retain_notices, source_inputs
from tests.support.distribution import ROOT


def inventory(tmp_path):
    license = tmp_path / "LICENSE.txt"
    license.write_text("original CPython license")
    notice = b"original dependency license"
    return {
        "stdlib_license": str(license),
        "base_prefix": str(tmp_path / "python"),
        "packages": [
            {
                "name": "pyte",
                "notices": [
                    {
                        "file": "pyte.dist-info/LICENSE",
                        "content_base64": base64.b64encode(notice).decode(),
                        "sha256": hashlib.sha256(notice).hexdigest(),
                    }
                ],
            }
        ],
    }


def test_original_notices_and_interpreter_license_are_retained(tmp_path):
    original = inventory(tmp_path)
    extras = Path(original["base_prefix"]) / "licenses"
    extras.mkdir(parents=True)
    (extras / "libffi.txt").write_text("original runtime library license")
    destination = tmp_path / "notices"
    retain_notices(original, destination, ROOT)
    assert (destination / "pyte/000-LICENSE").read_bytes() == b"original dependency license"
    assert (destination / "CPYTHON-LICENSE.txt").read_text() == "original CPython license"
    assert (
        destination / "python-runtime/libffi.txt"
    ).read_text() == "original runtime library license"
    assert (destination / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert (destination / "NOTICE").read_bytes() == (ROOT / "NOTICE").read_bytes()


@pytest.mark.parametrize("case", ["python-license", "dependency-license", "digest"])
def test_missing_or_tampered_original_license_fails(tmp_path, case):
    original = inventory(tmp_path)
    if case == "python-license":
        Path(original["stdlib_license"]).unlink()
    elif case == "dependency-license":
        original["packages"][0]["notices"] = []
    else:
        original["packages"][0]["notices"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        retain_notices(original, tmp_path / "notices", ROOT)


def test_freezer_analysis_requires_literal_original_binary_sources(tmp_path):
    original = tmp_path / "Analysis-00.toc"
    original.write_text(
        repr(
            (
                [],
                [
                    ("libpython.so", "/owned/libpython.so", "BINARY"),
                    ("module.py", "/owned/module.py", "PYSOURCE"),
                ],
            )
        )
    )
    assert analysis_binaries(original) == {"libpython.so": "/owned/libpython.so"}
    original.write_text("__import__('os').system('never execute')")
    with pytest.raises(ValueError):
        analysis_binaries(original)
    original.write_text(repr(([], [("module.py", "/owned/module.py", "PYSOURCE")])))
    with pytest.raises(ValueError, match="Missing original"):
        analysis_binaries(original)


def test_recipe_provenance_binds_the_lgpl_replacement_instructions():
    inputs = source_inputs(ROOT)
    for name in (
        "scripts/build_standalone.py",
        "scripts/standalone.py",
        "packaging/standalone/hooks/hook-pyte.py",
        "packaging/standalone/REPLACING-PYTE.md",
        "src/kuberich/runtime.py",
        "uv.lock",
    ):
        assert inputs[name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
