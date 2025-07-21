from setuptools import setup, find_packages
import os

# Read requirements
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="spyhunt",
    version="3.4.0",
    description="Comprehensive network scanning and vulnerability assessment tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Pymmdrza (forked from gotr00t0day)",
    url="https://github.com/Pymmdrza/spyhunt",
    packages=find_packages(where=".", include=["spyhunt", "spyhunt.*"]),
    package_dir={"": "."},
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "spyhunt=spyhunt.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
