# bits

`bits` is a cli tool and pure Python library for Bitcoin

## Dependencies

- Python 3.7+

## Installation

```bash
git clone https://github.com/jtraub91/bits.git
cd bits/
pip install .
```

### Install for development

```bash
pip install .[dev]
pre-commit install
```

## Usage

See the following for command line usage

```bash
bits -h
```

## Configuration

Configuration is not strictly necessary, but, a user may leverage a configuration file, nominally located at `~/.bits/config.[toml|json]`, for overriding CLI defaults, or for non-CLI usage.

## Donate

```text
DONATION-ADDRESS-HERE
```

## License

MIT License

Copyright (c) 2023 Jason Traub

See `LICENSE.txt` for details.
