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

    echo -e "${BLUE}Client Management:${NC}"
    echo "  1) Add Client                    (add-client.sh)"
    echo "  2) Remove Client                 (remove-client.sh)"
    echo "  3) List Clients                  (list-clients.sh)"
    echo "  4) Show Client Status            (client-status.sh)"
    echo "  5) Rotate Client Keys            (rotate-keys-client.sh)"
    echo ""

    echo -e "${BLUE}Client Configuration:${NC}"
    echo "  6) Show QR Code for Client       (qr-show.sh)"
    echo ""

    echo -e "${BLUE}Server Setup & Management:${NC}"
    echo "  7) Setup WireGuard Server        (setup-wireguard.sh)"
    echo "  8) Rotate Server Keys            (rotate-keys-server.sh)"
    echo "  9) Reset/Cleanup WireGuard       (reset-wireguard.sh)"
    echo ""

    echo -e "${BLUE}System:${NC}"
    echo "  10) Exit"
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
                run_script "add-client.sh" "Add Client"
                ;;
            2)
                run_script "remove-client.sh" "Remove or Revoke Client"
                ;;
            3)
                run_script "list-clients.sh" "List Clients"
                ;;
            4)
                run_script "client-status.sh" "Show Client Status"
                ;;
            5)
                run_script "rotate-keys-client.sh" "Rotate Client Keys"
                ;;
            6)
                run_script "qr-show.sh" "Show QR Code for Client"
                ;;
            7)
                run_script "setup-wireguard.sh" "Setup WireGuard Server"
                ;;
            8)
                run_script "rotate-keys-server.sh" "Rotate Server Keys"
                ;;
            9)
                run_script "reset-wireguard.sh" "Reset/Cleanup WireGuard"
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
