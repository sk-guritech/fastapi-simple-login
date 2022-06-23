#!/bin/bash
cd "$(dirname "$0")"
pip install pip-tools
pip-compile ./requirements/requirements.in
pip-sync ./requirements/requirements.txt
pre-commit install
