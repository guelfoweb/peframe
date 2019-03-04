#!/bin/bash

# PEFrame 6.0
# Debian/Ubuntu Installation

echo "Check for python3......"
if [ -z $(which python3) ]; then
	sudo apt -y install python3
	sudo apt -y install python3-dev
fi

echo "Check for pip3........."
if [ -z $(which pip3) ]; then
	sudo apt -y install python3-pip
fi

echo "Install libssl-dev....."
sudo apt -y install libssl-dev

echo "Install swig..........."
sudo apt -y install swig

echo "Install dependencies..."
pip3 install -r requirements.txt