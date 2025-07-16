from setuptools import setup, find_packages
import pathlib

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for Python<3.11
    import tomli as tomllib


def load_project_metadata():
    """Load project metadata from ``pyproject.toml`` if available."""
    path = pathlib.Path(__file__).with_name("pyproject.toml")
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f).get("project", {})


project = load_project_metadata()

setup(
    name=project.get("name", "jwtek"),
    version=project.get("version", "0.0.0"),
    description=project.get("description", ""),
    author=(project.get("authors") or [{}])[0].get("name", ""),
    packages=find_packages(),
    install_requires=project.get("dependencies", []),
    entry_points={
        "console_scripts": [f"{k} = {v}" for k, v in (project.get("scripts", {}).items())],
    },
    python_requires=project.get("requires-python", ">=3.6"),
)
