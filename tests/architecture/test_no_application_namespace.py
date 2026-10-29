"""The target architecture has no transitional ``application`` package."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
PACKAGES_ROOT = REPOSITORY_ROOT / "packages"
CORE_SOURCE = PACKAGES_ROOT / "core/src/cloud_dast"


def _production_sources() -> tuple[Path, ...]:
    return tuple(PACKAGES_ROOT.rglob("*.py"))


def test_application_namespace_has_no_python_modules() -> None:
    application = CORE_SOURCE / "application"
    assert not application.exists() or not any(application.rglob("*.py"))


def test_production_has_no_application_imports() -> None:
    violations = [
        path
        for path in _production_sources()
        if "cloud_dast.application" in path.read_text()
    ]
    assert violations == []


def test_runtime_does_not_import_reporting_package() -> None:
    runtime_sources = (CORE_SOURCE / "runtime").rglob("*.py")
    violations = [
        path for path in runtime_sources if "cloud_dast_reporting" in path.read_text()
    ]
    assert violations == []
