#!/bin/bash
# ============================================
# XSS Hunter v2.0 - Auto Installer
# Usage: chmod +x install.sh && ./install.sh
# ============================================

GREEN="\033[92m"
CYAN="\033[96m"
RED="\033[91m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "============================================"
echo "     XSS Hunter v2.0 - Auto Installer      "
echo "         Created by EnCrYpTeD05            "
echo "============================================"
echo -e "${RESET}"

# Python dependencies
echo -e "${CYAN}[*]${RESET} Installing Python dependencies..."
pip install -r requirements.txt
echo -e "${GREEN}[+]${RESET} Python dependencies installed!"

# Subfinder
echo -e "${CYAN}[*]${RESET} Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo -e "${GREEN}[+]${RESET} Subfinder installed!"

# Dalfox
echo -e "${CYAN}[*]${RESET} Installing Dalfox..."
go install github.com/hahwul/dalfox/v2@latest
echo -e "${GREEN}[+]${RESET} Dalfox installed!"

echo ""
echo -e "${GREEN}============================================${RESET}"
echo -e "${GREEN}   All tools installed successfully! 🎯    ${RESET}"
echo -e "${GREEN}   Run: python3 xsshunter.py -d target.com ${RESET}"
echo -e "${GREEN}============================================${RESET}"
