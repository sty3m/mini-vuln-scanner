# Contributing

Thanks for your interest in improving Mini Vulnerability Scanner.

## Before contributing

- Keep the project focused on authorized, ethical, read-only security assessment.
- Do not add features intended to exploit, brute-force, bypass authentication, or modify target systems.
- Keep dependencies minimal and document any new dependency.
- Avoid committing secrets, credentials, generated reports, or local environment files.

## Pull requests

1. Fork the repository and create a focused branch.
2. Make your changes and test them locally.
3. Update documentation when behavior or usage changes.
4. Open a pull request with a clear description of what changed and why.

## Development setup

Create an isolated environment and install the development dependencies:

```bash
python -m venv .venv
# Activate .venv using the command for your operating system.
python -m pip install -r requirements-dev.txt
```

## Running tests

Run the local test suite before opening a pull request:

```bash
python -m pytest -q
```

GitHub Actions runs the same suite on Python 3.10, 3.11, and 3.12.

## Code style

Follow standard Python conventions and keep functions small and readable. Prefer clear error handling and avoid unnecessary changes outside the scope of the contribution.
