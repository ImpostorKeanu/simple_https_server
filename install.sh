#!/bin/bash
wrap () {
    echo -e "\e[93m$1\e[0m" 
}

wrap 'Installing APT Pacakges'
apt-get update
apt-get install python3.7 python3-pip python3-openssl python3-pip libffi-dev
wrap 'Installing Python Packages'
python3 -m pip install -r requirements.txt
