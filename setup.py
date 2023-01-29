from setuptools import setup

setup(
    name="bits",
    version="0.1.0",
    install_requires=[],
    extras_require={
        "dev": [],
        "test": [],
    },
    entry_points={
        "console_scripts": ["bits = bits.cli:main"],
    },
)
