# Exodus

A python package with a universal build process.

## Installation

```bash
pip install exodus
```

## Development

### Prerequisites

Install the package with all development dependencies:

```bash
pip install -e .[all]
```

### Pre-commit Hooks

To set up the git hooks:

```bash
pre-commit install
```

To run the hooks manually on all files:

```bash
pre-commit run --all-files
```

### Running Tests (Planned)

```bash
pytest
```

## Usage

```bash
exodus --help
exodus build
```
