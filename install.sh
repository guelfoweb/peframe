#!/bin/bash

# ----------------------------------------------------------------------
# This file is part of peframe https://github.com/guelfoweb/peframe/
# ----------------------------------------------------------------------

if [[ $(id -u) -ne 0 ]]; then 
	echo "Please run as root" 
	exit 1
fi

peframe_version="6.0.2"
environment_test="Ubuntu Desktop 18.04.2 64bit"

echo "Installation script peframe $peframe_version"
echo -e "Tested on $environment_test\n"

read -rsp $'Press enter to continue...\n'

sudo apt -y install python3
sudo apt -y install python3-dev
sudo apt -y install python3-pip
sudo apt -y install libssl-dev
sudo apt -y install swig

echo -e "\nInstalling requirements via setup.py...\n"
sudo python3 setup.py install
