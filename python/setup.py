"""Module setup."""

import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "oberon"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="Michael Lodder <redmike7@gmail.com>",
        url="https://github.com/mikelodder7/oberon",
        packages=find_packages(),
        include_package_data=True,
        package_data={
            "": [
                "oberon.dll",
                "liboberon.dylib",
                "liboberon.so",
            ]
        },
        python_requires=">=3.7.3",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
        ],
    )
