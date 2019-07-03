#!/bin/bash

# ----------------------------------------------------------------------
# This file is part of peframe https://github.com/guelfoweb/peframe/
# ----------------------------------------------------------------------

if [[ $(id -u) -ne 0 ]]; then 
	echo "Please run as root" 
	exit 1
fi

peframe_version="6.0.3"
environment_test="Ubuntu Desktop 18.04.2 64bit"

echo "Installation script peframe $peframe_version"
echo -e "Tested on $environment_test\n"

read -rsp $'Press enter to continue...\n'

apt -y install python3
apt -y install python3-dev
apt -y install python3-pip
apt -y install libssl-dev
apt -y install swig

echo -e "\nInstalling requirements via setup.py...\n"
python3 setup.py install
