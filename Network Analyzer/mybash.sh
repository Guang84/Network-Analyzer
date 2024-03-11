#!/bin/bash

# Banner
# Banner
echo " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ "
echo "                                                                         B       "
echo "             ██████████          ██████        ████████████████████      C       "
echo "             ███████████         ██████       ██████████████████████     A       "
echo "             ███████ ████        ██████       ██████         ███████             "
echo "             ███████  ████       ██████       ██████         ███████     5th     "
echo "             ███████   █████     ██████       ██████         ███████             "
echo "             ███████    █████    ██████       ██████████████████████     S       "
echo "             ███████     █████   ██████       ██████████████████████     E       "
echo "             ███████      █████  ██████       ██████         ███████     M       "
echo "             ███████       ████████████       ██████         ███████             "
echo "             ███████        ███████████       ██████         ███████     P       "
echo "             ███████         ██████████       ██████         ███████     J       "      
echo "                                                                                 "
echo "                                   NETWORK ANALYZER                   -AZ_SEP    "
echo " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ "

# Menu options
echo "Select an option:"
echo "1. Enable Monitor Mode"
echo "2. Network Deauthentication"
echo "3. Handshake Captured"
echo "4. WiFi Network Encryption Vulnerability Testing"
echo "5. Network Monitoring"
echo "6. Disable Monitoring Mode"

# Read user input
read -p "Enter your choice (1/3/3/5/6): " choice

# Perform actions based on user choice
case "$choice" in
    1)
        # Network Deauthentication
        echo "Performing network deauthentication..."
        # Get the list of access points and clients
        sudo airodump-ng <INTERFACE_NAME> --essid <ESSID> --write <OUTPUT_FILE>
        # Deauthenticate all connected clients from the access point
        sudo aireplay-ng --deauth 100 -a <AP_MAC_ADDRESS> <INTERFACE_NAME>
        # Stop the airodump-ng process
        sudo killall airodump-ng
        ;;
    3)
        # Handshake Captured
        echo "Capturing handshake..."
        # Start airodump-ng to capture handshake
        sudo airodump-ng -c <CHANNEL> --bssid <AP_MAC_ADDRESS> -w <OUTPUT_FILE> <INTERFACE_NAME>
        # Wait for a client to connect to the access point
        while true; do
            if [ $(sudo airodump-ng -c <CHANNEL> --bssid <AP_MAC_ADDRESS> <INTERFACE_NAME> | grep -c "STATION") -gt 1 ]; then
                break
            fi
        done
        # Stop the airodump-ng process
        sudo killall airodump-ng
        # Check if the handshake was captured
        if [ -f <OUTPUT_FILE>.cap ]; then
            echo "Handshake captured successfully!"
            # Analyze the captured handshake
            sudo aircrack-ng <OUTPUT_FILE>.cap
        else
            echo "Failed to capture handshake."
        fi
        ;;
    3)
        # WiFi Network Encryption Vulnerability Testing
        echo "Testing WiFi network encryption vulnerabilities..."
        # Start airodump-ng to capture handshake
        sudo airodump-ng -c <CHANNEL> --bssid <AP_MAC_ADDRESS> -w <OUTPUT_FILE> <INTERFACE_NAME>
        # Wait for a client to connect to the access point
        while true; do
            if [ $(sudo airodump-ng -c <CHANNEL> --bssid <AP_MAC_ADDRESS> <INTERFACE_NAME> | grep -c "STATION") -gt 1 ]; then
                break
            fi
        done
        # Stop the airodump-ng process
        sudo killall airodump-ng
        # Check if the handshake was captured
        if [ -f <OUTPUT_FILE>.cap ]; then
            echo "Handshake captured successfully!"
            # Test for WPA/WPA3-PSK vulnerability using aircrack-ng
            sudo aircrack-ng -w <WORDLIST_FILE> <OUTPUT_FILE>.cap
        else
            echo "Failed to capture handshake."
        fi
        ;;
    5)
        # Network Monitoring
        echo "Monitoring network traffic..."
        # Monitor network traffic using tcpdump
        sudo tcpdump -i <INTERFACE_NAME> -n -vv
        fi
        ;;
    6)
        #Disable Monitoring Mode
        echo "Disabling Network Monitoring Mode...."
        sudo airmon-ng stop wlan0mon
        if []
        fi
        ;;
    *)
        echo "Invalid choice. Please select a valid option (1/3/3/5)."
        ;;
esac