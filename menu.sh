#!/bin/bash
################################################################################
# WireGuard Management Menu
# Description: Interactive menu for WireGuard management scripts
# Usage: ./menu.sh
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

################################################################################
# HELPERS
################################################################################

# Inline restart/reload. No separate script — these are just systemctl + wg
# syncconf, and keeping them inline avoids one more file to maintain.
#   Reload  = hot reconfigure (wg syncconf). Picks up peer add/remove/toggle
#             changes without dropping connected peers. Will NOT pick up
#             interface-level changes (Address, ListenPort, etc).
#   Restart = full wg-quick restart. Picks up everything but drops all peers
#             for a few seconds.
restart_or_reload() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This action requires root — re-run the menu with sudo"
        return
    fi

    local -a servers
    mapfile -t servers < <(detect_servers)
    if [[ ${#servers[@]} -eq 0 ]]; then
        print_warning "No WireGuard interfaces found"
        return
    fi

    local iface
    if [[ ${#servers[@]} -eq 1 ]]; then
        iface="${servers[0]}"
    else
        echo "Interfaces:"
        local i=1
        for s in "${servers[@]}"; do
            printf "  %d) %s\n" "$i" "$s"
            ((i++)) || true
        done
        read -rp "Select interface (1-${#servers[@]}): " sel
        if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#servers[@]} )); then
            print_error "Invalid selection"
            return
        fi
        iface="${servers[$((sel-1))]}"
    fi

    echo ""
    echo "  1) Reload   (hot — peers stay connected, picks up peer changes only)"
    echo "  2) Restart  (full — drops & re-establishes everything)"
    echo "  3) Cancel"
    read -rp "Action for ${iface}: " action
    case "$action" in
        1)
            if wg syncconf "$iface" <(wg-quick strip "$iface") 2>/dev/null; then
                print_success "${iface}: reloaded (peers unaffected)"
                log_audit "RELOAD" "interface=${iface}"
            else
                print_error "${iface}: reload failed — try a full restart"
            fi
            ;;
        2)
            if systemctl restart "wg-quick@${iface}"; then
                print_success "${iface}: restarted"
                log_audit "RESTART" "interface=${iface}"
            else
                print_error "${iface}: restart failed (see: journalctl -u wg-quick@${iface})"
            fi
            ;;
        3|"")
            print_info "Cancelled"
            ;;
        *)
            print_error "Invalid action"
            ;;
    esac
}

################################################################################
# MENU
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
    echo "  1) Add Peer (Client or Site)         (add-peer.sh)"
    echo "  2) Remove Peer                       (remove-peer.sh)"
    echo "  3) List/View Peers                   (list-peer.sh)"
    echo "  4) Toggle Peer (enable/disable)      (toggle-peer.sh)"
    echo ""

    echo -e "${BLUE}Peer Configuration:${NC}"
    echo "  5) Show QR Code for Client           (show-qr.sh)"
    echo ""

    echo -e "${BLUE}Server Setup & Management:${NC}"
    echo "  6) Setup WireGuard Server            (setup.sh)"
    echo "  7) Restart / Reload Server"
    echo "  8) Rotate Keys (Server or Peer)      (rotate-keys.sh)"
    echo "  9) Reset/Cleanup WireGuard           (reset.sh)"
    echo ""

    echo -e "${BLUE}Auditing:${NC}"
    echo " 10) Connection Logging                (log-connection.sh)"
    echo ""

    echo -e "${BLUE}System:${NC}"
    echo " 11) Exit"
    echo ""
    echo "=========================================="
    echo ""
}

run_script() {
    local script="$1"
    local script_name="$2"
    local script_path="${SCRIPT_DIR}/${script}"

    if [[ ! -f "$script_path" ]]; then
        print_error "Script not found: $script_path"
        echo ""
        read -rp "Press Enter to continue..."
        return
    fi

    if [[ ! -x "$script_path" ]]; then
        print_warning "Script is not executable. Making it executable..."
        chmod +x "$script_path"
    fi

    echo ""
    print_info "Launching: $script_name"
    echo "=========================================="
    echo ""

    set +e
    "$script_path"
    local exit_code=$?
    set -e

    echo ""
    echo "=========================================="
    if [[ $exit_code -eq 0 ]]; then
        print_success "Script completed successfully"
    else
        print_warning "Script exited with code: $exit_code"
    fi
    echo ""
    read -rp "Press Enter to continue..."
}

################################################################################
# MAIN
################################################################################

main() {
    while true; do
        show_menu
        read -rp "Select an option (1-11): " choice
        case $choice in
            1)  run_script "add-peer.sh"        "Add Peer (Client or Site)" ;;
            2)  run_script "remove-peer.sh"     "Remove Peer" ;;
            3)  run_script "list-peer.sh"       "List/View Peers" ;;
            4)  run_script "toggle-peer.sh"     "Toggle Peer (enable/disable)" ;;
            5)  run_script "show-qr.sh"         "Show QR Code for Client" ;;
            6)  run_script "setup.sh" "Setup WireGuard Server" ;;
            7)
                echo ""
                restart_or_reload
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            8)  run_script "rotate-keys.sh"     "Rotate Keys (Server or Peer)" ;;
            9)  run_script "reset.sh" "Reset/Cleanup WireGuard" ;;
            10) run_script "log-connection.sh"  "Connection Logging" ;;
            11)
                echo ""
                print_info "Exiting WireGuard Management Menu"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid selection. Please choose 1-11."
                echo ""
                read -rp "Press Enter to continue..."
                ;;
        esac
    done
}

main "$@"
