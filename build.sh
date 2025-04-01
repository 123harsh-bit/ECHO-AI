#!/bin/bash
# Install Linux Bluetooth dependencies
apt-get update && apt-get install -y \
    bluez \
    libbluetooth-dev

# Then install Python requirements
pip install -r requirements.txt
