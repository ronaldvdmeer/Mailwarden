#!/bin/bash
set -euo pipefail

# Mailwarden Update Script
# Updates the Mailwarden installation and restarts the systemd service

# Configuration
INSTALL_DIR="/opt/Mailwarden"
SERVICE_NAME="mailwarden"
USER="mailwarden"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_service() {
    if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
        log_error "Service ${SERVICE_NAME}.service not found"
        exit 1
    fi
}

check_directory() {
    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "Installation directory $INSTALL_DIR not found"
        exit 1
    fi
}

backup_config() {
    if [ -f "$INSTALL_DIR/config.yml" ]; then
        cp "$INSTALL_DIR/config.yml" "/tmp/mailwarden-config-backup-$(date +%s).yml"
        log_info "Config backed up to /tmp/"
    fi
}

# Main update process
main() {
    log_info "Starting Mailwarden update..."
    
    # Pre-flight checks
    check_root
    check_directory
    check_service
    
    # Backup config
    backup_config
    
    # Stop service
    log_info "Stopping ${SERVICE_NAME} service..."
    systemctl stop "$SERVICE_NAME" || {
        log_error "Failed to stop service"
        exit 1
    }
    
    # Store current commit for rollback
    cd "$INSTALL_DIR"
    PREVIOUS_COMMIT=$(sudo -u "$USER" git rev-parse HEAD 2>/dev/null || echo "unknown")
    log_info "Current commit: ${PREVIOUS_COMMIT:0:8}"
    
    # Git pull
    log_info "Pulling latest changes from git..."
    if sudo -u "$USER" git pull origin main; then
        NEW_COMMIT=$(sudo -u "$USER" git rev-parse HEAD 2>/dev/null || echo "unknown")
        log_info "Updated to commit: ${NEW_COMMIT:0:8}"
        
        if [ "$PREVIOUS_COMMIT" = "$NEW_COMMIT" ]; then
            log_info "Already up to date, no changes pulled"
        fi
    else
        log_error "Git pull failed"
        log_warn "Starting service with previous version..."
        systemctl start "$SERVICE_NAME"
        exit 1
    fi
    
    # Update dependencies
    log_info "Updating Python dependencies..."
    if sudo -u "$USER" "$INSTALL_DIR/venv/bin/pip" install -e . --quiet; then
        log_info "Dependencies updated successfully"
    else
        log_warn "Dependency update had issues, but continuing..."
    fi
    
    # Start service
    log_info "Starting ${SERVICE_NAME} service..."
    systemctl start "$SERVICE_NAME" || {
        log_error "Failed to start service"
        
        # Offer rollback
        if [ "$PREVIOUS_COMMIT" != "unknown" ] && [ "$PREVIOUS_COMMIT" != "$NEW_COMMIT" ]; then
            log_warn "Attempting rollback to $PREVIOUS_COMMIT..."
            sudo -u "$USER" git reset --hard "$PREVIOUS_COMMIT"
            systemctl start "$SERVICE_NAME" && log_info "Rollback successful" || log_error "Rollback failed"
        fi
        exit 1
    }
    
    # Wait for service to stabilize
    sleep 2
    
    # Check service status
    log_info "Checking service status..."
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "✓ Service is running"
    else
        log_error "✗ Service is not running"
        systemctl status "$SERVICE_NAME" --no-pager
        exit 1
    fi
    
    # Show recent logs
    log_info "Recent logs:"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager
    
    log_info "Update completed successfully!"
    log_info "Monitor logs with: journalctl -u ${SERVICE_NAME} -f"
}

# Run main
main "$@"
