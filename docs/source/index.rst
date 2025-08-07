bits
==================

bits is a pure Python implementation of Bitcoin

Dependencies
============

Python 3.7+

Installation
============

.. code-block:: bash

    pip install bits


Install for development
=======================

.. code-block:: bash

   git clone https://github.com/jtraub91/bits.git
   cd bits/
   pip install -e .[dev]
   pre-commit install

Configuration
============

A configuration file is not strictly necessary, but may be leveraged, nominally located at ``~/.bits/config.[toml|json]``, for overriding CLI defaults.

See :doc:`conf/` for default configuration files.

Config file support
-------------------

`TOML <https://toml.io>`_ is preferred for configuration files but is natively supported only on Python 3.11 and up; on the contrary, `JSON <https://www.json.org>`_ is supported for all Python versions. Therefore, for all Python versions, if ``~/.bits/config.json`` is present, it will be used, but for Python 3.11+, if ``~/.bits/config.toml`` is present, it will be used instead.


.. toctree::
   :maxdepth: 2
   :caption: Table of Contents:

   cli
   api
