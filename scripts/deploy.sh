#!/usr/bin/env bash
#
# Ironclaw Deployment Script
# Enterprise-grade OpenClaw fork
#

set -euo pipefail

# Configuration
REPO_URL="https://github.com/yslim77/ironclaw.git"
INSTALL_DIR="/usr/local/lib/node_modules/ironclaw"
CONFIG_DIR="$HOME/.openclaw"
LOG_DIR="/tmp/openclaw"
REQUIRED_NODE_VERSION="22"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check command availability
check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

# Check Node.js version
check_node() {
    log_info "Checking Node.js version..."
    
    if ! check_command node; then
        log_error "Node.js is not installed. Please install Node.js $REQUIRED_NODE_VERSION or later."
        exit 1
    fi
    
    local node_version
    node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    
    if [[ "$node_version" -lt "$REQUIRED_NODE_VERSION" ]]; then
        log_error "Node.js $REQUIRED_NODE_VERSION or later is required. Found: $(node --version)"
        exit 1
    fi
    
    log_success "Node.js $(node --version) is installed"
}

# Check pnpm
check_pnpm() {
    log_info "Checking pnpm..."
    
    if ! check_command pnpm; then
        log_warn "pnpm not found. Installing..."
        npm install -g pnpm
    fi
    
    log_success "pnpm $(pnpm --version) is installed"
}

# Check 1Password CLI (optional)
check_1password() {
    log_info "Checking 1Password CLI..."
    
    if check_command op; then
        log_success "1Password CLI (op) is installed"
        return 0
    else
        log_warn "1Password CLI not found. Secret management via 1Password will be disabled."
        return 1
    fi
}

# Clone or update repository
clone_repo() {
    log_info "Cloning Ironclaw repository..."
    
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        log_info "Repository exists. Pulling latest changes..."
        cd "$INSTALL_DIR"
        git pull origin main
    else
        sudo mkdir -p "$(dirname $INSTALL_DIR)"
        sudo rm -rf "$INSTALL_DIR"
        sudo git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    log_success "Repository ready at $INSTALL_DIR"
}

# Install dependencies
install_deps() {
    log_info "Installing dependencies..."
    
    cd "$INSTALL_DIR"
    pnpm install --frozen-lockfile
    
    log_success "Dependencies installed"
}

# Build project
build_project() {
    log_info "Building project..."
    
    cd "$INSTALL_DIR"
    pnpm build
    
    log_success "Project built successfully"
}

# Setup configuration
setup_config() {
    log_info "Setting up configuration..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Copy production config if it doesn't exist
    local config_file="$CONFIG_DIR/openclaw.json"
    local production_config="$INSTALL_DIR/config/openclaw.production.json"
    
    if [[ -f "$production_config" ]]; then
        if [[ -f "$config_file" ]]; then
            log_warn "Config exists at $config_file. Skipping copy."
            log_info "You may want to review and merge changes from $production_config"
        else
            cp "$production_config" "$config_file"
            log_success "Production config copied to $config_file"
        fi
    else
        log_warn "Production config not found at $production_config"
    fi
    
    # Set permissions
    chmod 700 "$CONFIG_DIR"
}

# Install CLI globally
install_cli() {
    log_info "Installing Ironclaw CLI..."
    
    # Link the CLI globally
    cd "$INSTALL_DIR"
    
    # Create symlink for openclaw command
    if [[ -f "$INSTALL_DIR/dist/index.js" ]]; then
        sudo ln -sf "$INSTALL_DIR/dist/index.js" /usr/local/bin/ironclaw
        log_success "CLI symlinked as 'ironclaw'"
    fi
    
    # Link package globally as openclaw
    if ! npm link &>/dev/null; then
        log_warn "npm link failed, using manual symlink"
    fi
}

# Install service (macOS LaunchAgent)
install_service() {
    log_info "Installing LaunchAgent service..."
    
    local service_file="$HOME/Library/LaunchAgents/ai.ironclaw.gateway.plist"
    local launchagent_dir="$HOME/Library/LaunchAgents"
    
    mkdir -p "$launchagent_dir"
    
    cat > "$service_file" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.ironclaw.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>/usr/local/lib/node_modules/ironclaw/dist/index.js</string>
        <string>gateway</string>
        <string>--port</string>
        <string>18789</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENCLAW_GATEWAY_PORT</key>
        <string>18789</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/openclaw/ironclaw-gateway.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/openclaw/ironclaw-gateway-error.log</string>
</dict>
</plist>
EOF
    
    # Unload old service if exists
    launchctl unload "$service_file" &>/dev/null || true
    
    # Load new service
    launchctl load "$service_file"
    launchctl start ai.ironclaw.gateway
    
    log_success "LaunchAgent installed and started"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Wait for service to start
    sleep 2
    
    # Check if gateway is responding
    if curl -s http://127.0.0.1:18789/ > /dev/null 2>&1 || true; then
        log_success "Gateway is responding"
    else
        log_warn "Gateway may not be fully started yet. Check logs with: tail -f /tmp/openclaw/ironclaw-gateway.log"
    fi
    
    log_info ""
    log_info "Deployment Status:"
    log_info "=================="
    log_info "Repository: $INSTALL_DIR"
    log_info "Config: $CONFIG_DIR/openclaw.json"
    log_info "Logs: $LOG_DIR"
    log_info "Dashboard: http://127.0.0.1:18789/"
    log_info "Metrics: http://127.0.0.1:18789/metrics"
    log_info ""
}

# Print usage
usage() {
    cat << EOF
Ironclaw Deployment Script

Usage: $0 [OPTIONS] [COMMAND]

Commands:
    install     Full installation (default)
    update      Update existing installation
    uninstall   Remove Ironclaw
    start       Start the gateway service
    stop        Stop the gateway service
    restart     Restart the gateway service
    status      Check service status
    logs        View gateway logs

Options:
    -h, --help      Show this help message
    --no-service    Skip LaunchAgent installation
    --dev           Install in development mode

Examples:
    $0 install              # Full installation
    $0 update               # Update to latest
    $0 restart              # Restart gateway
    $0 status               # Check status

EOF
}

# Main installation flow
do_install() {
    log_info "Starting Ironclaw deployment..."
    
    check_node
    check_pnpm
    check_1password
    clone_repo
    install_deps
    build_project
    setup_config
    install_cli
    
    if [[ "$SKIP_SERVICE" != "true" ]]; then
        install_service
    fi
    
    verify_deployment
    
    log_success "Ironclaw deployed successfully!"
}

# Update flow
do_update() {
    log_info "Updating Ironclaw..."
    
    check_node
    check_pnpm
    
    cd "$INSTALL_DIR"
    git pull origin main
    pnpm install --frozen-lockfile
    pnpm build
    
    log_success "Ironclaw updated!"
    log_info "Restart the service with: launchctl kickstart -k gui/$(id -u)/ai.ironclaw.gateway"
}

# Uninstall
do_uninstall() {
    log_info "Uninstalling Ironclaw..."
    
    # Stop and unload service
    launchctl stop ai.ironclaw.gateway &>/dev/null || true
    launchctl unload "$HOME/Library/LaunchAgents/ai.ironclaw.gateway.plist" &>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/ai.ironclaw.gateway.plist"
    
    # Remove symlink
    sudo rm -f /usr/local/bin/ironclaw
    
    # Remove installation
    sudo rm -rf "$INSTALL_DIR"
    
    log_success "Ironclaw uninstalled"
}

# Start service
do_start() {
    log_info "Starting Ironclaw gateway..."
    launchctl start ai.ironclaw.gateway || true
    log_success "Gateway started"
}

# Stop service
do_stop() {
    log_info "Stopping Ironclaw gateway..."
    launchctl stop ai.ironclaw.gateway || true
    log_success "Gateway stopped"
}

# Restart service
do_restart() {
    log_info "Restarting Ironclaw gateway..."
    launchctl kickstart -k "gui/$(id -u)/ai.ironclaw.gateway" || {
        log_warn "Using fallback restart method..."
        launchctl stop ai.ironclaw.gateway || true
        sleep 1
        launchctl start ai.ironclaw.gateway
    }
    log_success "Gateway restarted"
}

# Check status
do_status() {
    log_info "Checking Ironclaw status..."
    
    # Check if service is loaded
    if launchctl list | grep -q "ai.ironclaw.gateway"; then
        log_info "Service: ai.ironclaw.gateway"
        launchctl list | grep "ai.ironclaw.gateway"
    else
        log_warn "Service not loaded"
    fi
    
    # Check if port is open
    if nc -z 127.0.0.1 18789 2>/dev/null; then
        log_success "Gateway is listening on port 18789"
    else
        log_warn "Gateway is not listening on port 18789"
    fi
}

# View logs
do_logs() {
    local log_file="/tmp/openclaw/ironclaw-gateway.log"
    if [[ -f "$log_file" ]]; then
        tail -f "$log_file"
    else
        log_error "Log file not found: $log_file"
    fi
}

# Parse arguments
SKIP_SERVICE=false
COMMAND="install"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        --no-service)
            SKIP_SERVICE=true
            shift
            ;;
        --dev)
            log_info "Development mode enabled"
            shift
            ;;
        install|update|uninstall|start|stop|restart|status|logs)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Execute command
case "$COMMAND" in
    install)
        do_install
        ;;
    update)
        do_update
        ;;
    uninstall)
        do_uninstall
        ;;
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_restart
        ;;
    status)
        do_status
        ;;
    logs)
        do_logs
        ;;
    *)
        usage
        exit 1
        ;;
esac
