#!/bin/bash
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install it first."
    exit 1
fi
echo "Installing Python packages..."
python3 -m pip install --user requests colorama bs4 pycryptodomex --break-system-packages
if [ $? -eq 0 ]; then
    echo "Packages installed successfully."
else
    echo "Failed to install packages."
    exit 1
fi
