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

## Analyze

`exodus analyze` runs clang-based AST analysis in isolated worker subprocesses.
The main process does not parse translation units itself; it merges worker JSON
results and then runs the cross-TU phase on aggregated facts. This avoids the
shared-`libclang` threading model that tends to hang or crash on larger runs.

Relevant project config fields:

```json
{
  "clang_library_file": "/path/to/libclang.so",
  "clang_worker_timeout_sec": 30,
  "clang_worker_parallelism": 4,
  "project_headers_only": true,
  "src_pattern_for_headers": ["src/**/*.hpp", "include/**/*.hpp"],
  "clang_parse_only_on_timeout": true,
  "clang_parse_only_on_crash": true
}
```

`clang_worker_parallelism` limits concurrent clang subprocesses and defaults to
`4`, matching the analyze `--jobs` default. The parse-only fallback flags keep
cross-TU facts available for a file even if the full AST heuristic pass timed
out or the worker crashed. `project_headers_only` defaults to `true` and keeps
the header scan focused on project-local headers that are actually reachable
from the configured source files. `src_pattern_for_headers` can further narrow
that set; if omitted, Exodus derives header globs from the configured source
patterns by mapping source suffixes like `.cpp` or `.cc` to `.h`, `.hh`, `.hpp`
and `.hxx`.

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
