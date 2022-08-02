#!/bin/bash

python3 -m build
python3 python3 -m twine upload --repository pypi dist/*
