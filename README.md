# Exodus

Exodus is a Python-based build and analysis tool for native projects.

It is designed to keep the common build workflow simple:

- build C and C++ projects from `exodus.json`
- rebuild only what is out of date
- link final artifacts automatically
- support multi-project workspaces
- integrate static analysis and packaging workflows

## Status

Exodus is under active development. Interfaces, configuration details, and
project layout may still change.

## Installation

```bash
pip install exodus
```

For development:

```bash
pip install -e .[all]
```

## Quick Start

Create a project configuration:

```json
{
  "name": "hello",
  "sources": ["src/**/*.c", "src/**/*.cpp"],
  "search_paths": ["include"],
  "compiler": {
    "name": "clang++",
    "lang_standard": "20"
  }
}
```

Then run:

```bash
exodus --help
exodus build
```

## What Exodus Handles

- source discovery from configured globs
- project-scoped build directories
- incremental rebuilds based on source and dependency timestamps
- linking executables and libraries
- custom compiler support
- optional analysis, dependency, extraction, package, and SBOM tooling

## Development

### Pre-commit

```bash
pre-commit install
pre-commit run --all-files
```

### Tests

```bash
pytest
```

## Repository Layout

- [exodus](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus): package source
- [tests](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/tests): automated tests
- [spec](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/spec): notes and design documents
- [LICENSE](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/LICENSE): license terms

## License

Exodus is distributed under the license in [LICENSE](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/LICENSE).

