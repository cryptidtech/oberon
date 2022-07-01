#!/bin/bash

set -xv
mkdir -p build/python/src
cp pyproject.toml build/python/
cp Cargo.toml.python build/python/Cargo.toml
cp src/*.rs build/python/src/
cp LICENSE build/python
cp ../README.md build/

maturin publish --cargo-extra-args="--features=python" --no-sdist --manifest-path=build/python/Cargo.toml