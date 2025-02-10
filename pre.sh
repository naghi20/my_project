#!/bin/bash

# Update package list
sudo apt-get update

# Install Python3 and pip
sudo apt-get install -y python3 python3-pip

# Install required Python packages
pip3 install tkinter

# Create the Python script file
cat <<EOL > expense_manager.py
$(cat expense_manager.py)
EOL

# Make the Python script executable
chmod +x expense_manager.py

echo "Setup complete! Run the application with: python3 expense_manager.py"
