#!/bin/bash

# Vulnerability Prioritizer Quick Start
# This script sets up and runs the vulnerability prioritization system

echo "Vulnerability Prioritization System - Quick Start"
echo "====================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

echo "Python 3 found"

# Install required packages
echo "Installing required packages..."
pip3 install requests --break-system-packages --quiet 2>/dev/null || pip3 install requests --quiet 2>/dev/null

# Check for input files
echo ""
echo "Checking files..."

if [ -f "vulnerability_prioritizer.py" ]; then
    echo "Found: vulnerability_prioritizer.py"
else
    echo "Missing: vulnerability_prioritizer.py"
    exit 1
fi

if [ -f "prioritizer_config.json" ]; then
    echo "Found: prioritizer_config.json"
else
    echo "Missing: prioritizer_config.json"
    exit 1
fi

# Menu
echo ""
echo "What would you like to do?"
echo "1) Run prioritization demo"
echo "2) View configuration"
echo "3) Open dashboard (browser)"
echo "4) View README documentation"
echo "5) Exit"
echo ""
read -p "Select option (1-5): " choice

case $choice in
    1)
        echo ""
        echo "Running vulnerability prioritization..."
        echo "----------------------------------------"
        python3 vulnerability_prioritizer.py
        echo ""
        echo "Complete! Check prioritized_vulnerabilities.csv for results"
        ;;
    2)
        echo ""
        echo "Current Configuration:"
        echo "------------------------"
        cat prioritizer_config.json | python3 -m json.tool
        ;;
    3)
        echo ""
        echo "Opening dashboard in browser..."
        if command -v xdg-open &> /dev/null; then
            xdg-open vulnerability_dashboard.html
        elif command -v open &> /dev/null; then
            open vulnerability_dashboard.html
        else
            echo "Please open vulnerability_dashboard.html manually in your browser"
        fi
        ;;
    4)
        echo ""
        if [ -f "README.md" ]; then
            less README.md
        else
            echo "README.md not found"
        fi
        ;;
    5)
        echo "Goodbye!"
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

echo ""
echo "Run this script again for more options."
