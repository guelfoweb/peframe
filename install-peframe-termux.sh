#!/bin/bash

# ----------------------------------------------------------------------
# This file is part of peframe https://github.com/guelfoweb/peframe/
# ----------------------------------------------------------------------

peframe_version="6.0.3"
environment_test="Termux Android"

echo "Installation script peframe $peframe_version"
echo -e "Tested on $environment_test\n"

read -rsp $'Press enter to continue...\n'

pkg update -y
pkg upgrade -y

pkg install -y git
pkg install -y python
pkg install -y python-dev
pkg install -y clang
pkg install -y swig
pkg install -y openssl-dev
pkg install -y libffi-dev
pkg install -y sox

python3 setup.py install
