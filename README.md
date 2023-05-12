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
pip install -e .[dev]
pre-commit install
```

## Usage

See the following for command line usage

```bash
bits -h
```

## Configuration

A configuration file is not strictly necessary, but may be leveraged, nominally located at `~/.bits/config.[toml|json]`, for overriding CLI defaults.

See [conf/](/conf/) for default configuration files.

### Config file support

[TOML](https://toml.io) is preferred for configuration files but is natively supported only on Python 3.11 and up; on the contrary, [JSON](https://www.json.org) is supported for all Python versions. Therefore, for all Python versions, if `~/.bits/config.json` is present, it will be used, but for Python 3.11+, if `~/.bits/config.toml` is present, it will be used instead.

## Donate

```text
1GjPvTLYLNodnBJ969DWHcqBMP3pa5tsV3
```

## License

MIT License

Copyright (c) 2023 Jason Traub

See `LICENSE.txt` for details.
