from setuptools import setup

setup(
    name="bits",
    version="0.0.1",
    install_requires=[
        "ecdsa",
    ],
    extras_require={
        "dev": [],
        "test": [],
    },
    entry_points={
        "console_scripts": ["bits = bits.cli:main"],
    },
)
