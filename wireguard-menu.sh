#!/bin/bash
################################################################################
# WireGuard Management Menu
# Description: Interactive menu for WireGuard management scripts
# Usage: ./wireguard-menu.sh
################################################################################

set -euo pipefail

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() {
    print_error "$1"
    exit 1
}

check_script_exists() {
    local script="$1"
    if [[ -f "$script" ]]; then
        return 0
    else
        return 1
    fi
}

################################################################################
# MENU FUNCTIONS
################################################################################

show_header() {
    clear
    echo ""
    echo "=========================================="
    echo -e "  ${CYAN}WireGuard Management Menu${NC}"
    echo "=========================================="
    echo ""
}

show_menu() {
    show_header

    echo -e "${BLUE}Peer Management:${NC}"
    echo "  1) Add Peer (Client or Site)     (add-peer.sh)"
    echo "  2) Remove Peer                   (remove-peer.sh)"
    echo "  3) List Peers                    (list-clients.sh)"
    echo "  4) Show Peer Status              (client-status.sh)"
    echo ""

    echo -e "${BLUE}Peer Configuration:${NC}"
    echo "  5) Show QR Code for Client       (qr-show.sh)"
    echo ""

    echo -e "${BLUE}Server Setup & Management:${NC}"
    echo "  6) Setup WireGuard Server        (setup-wireguard.sh)"
    echo "  7) Rotate Keys (Server or Peer)  (rotate-keys.sh)"
    echo "  8) Reset/Cleanup WireGuard       (reset-wireguard.sh)"
    echo ""

    echo -e "${BLUE}Remote Site Configuration:${NC}"
    echo "  9) Setup Remote Site             (setup-site-remote.sh)"
    echo ""

    echo -e "${BLUE}System:${NC}"
    echo " 10) Exit"
    echo ""
    echo "=========================================="
    echo ""
}

run_script() {
    local script="$1"
    local script_name="$2"

    if ! check_script_exists "$script"; then
        print_error "Script not found: $script"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi

    if [[ ! -x "$script" ]]; then
        print_warning "Script is not executable. Making it executable..."
        chmod +x "$script"
    fi

    echo ""
    print_info "Launching: $script_name"
    echo "=========================================="
    echo ""

    # Run the script
    ./"$script"

    local exit_code=$?
    echo ""
    echo "=========================================="
    if [[ $exit_code -eq 0 ]]; then
        print_success "Script completed successfully"
    else
        print_warning "Script exited with code: $exit_code"
    fi
    echo ""
    read -p "Press Enter to continue..."
}

################################################################################
# MAIN
################################################################################

main() {
    while true; do
        show_menu

        read -p "Select an option (1-10): " choice

        case $choice in
            1)
                run_script "add-peer.sh" "Add Peer (Client or Site)"
                ;;
            2)
                run_script "remove-peer.sh" "Remove Peer"
                ;;
            3)
                run_script "list-clients.sh" "List Peers"
                ;;
            4)
                run_script "client-status.sh" "Show Peer Status"
                ;;
            5)
                run_script "qr-show.sh" "Show QR Code for Client"
                ;;
            6)
                run_script "setup-wireguard.sh" "Setup WireGuard Server"
                ;;
            7)
                run_script "rotate-keys.sh" "Rotate Keys (Server or Peer)"
                ;;
            8)
                run_script "reset-wireguard.sh" "Reset/Cleanup WireGuard"
                ;;
            9)
                run_script "setup-site-remote.sh" "Setup Remote Site"
                ;;
            10)
                echo ""
                print_info "Exiting WireGuard Management Menu"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid selection. Please choose 1-10."
                echo ""
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

main "$@"
