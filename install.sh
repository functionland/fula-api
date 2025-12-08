#!/bin/bash
#
# Fula Gateway Installation Script
# Installs and configures the Fula S3-compatible gateway with security best practices
#
# Usage: sudo ./install.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FULA_USER="fula"
FULA_GROUP="fula"
FULA_HOME="/var/lib/fula"
FULA_CONFIG="/etc/fula"
FULA_LOG="/var/log/fula"
FULA_BIN="/usr/local/bin"
ENV_FILE="${FULA_CONFIG}/.env"
NGINX_CONF="/etc/nginx/sites-available/fula-gateway"
NGINX_ENABLED="/etc/nginx/sites-enabled/fula-gateway"

# Default values
DEFAULT_GATEWAY_PORT="8080"
DEFAULT_IPFS_PORT="5001"
DEFAULT_IPFS_GATEWAY_PORT="8081"

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check Ubuntu version
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. This script is designed for Ubuntu."
        exit 1
    fi
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu but detected: $ID"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    log_info "Detected OS: $PRETTY_NAME"
}

# Install system dependencies
install_dependencies() {
    log_info "Updating package lists..."
    apt-get update -qq
    
    log_info "Installing dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl \
        wget \
        gnupg \
        ca-certificates \
        lsb-release \
        software-properties-common \
        nginx \
        certbot \
        python3-certbot-nginx \
        ufw \
        fail2ban \
        jq \
        > /dev/null
    
    log_success "Dependencies installed"
}

# Install Docker if needed
install_docker() {
    if command -v docker &> /dev/null; then
        log_info "Docker already installed: $(docker --version)"
        return 0
    fi
    
    log_info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    
    # Add fula user to docker group
    usermod -aG docker ${FULA_USER} 2>/dev/null || true
    
    log_success "Docker installed"
}

# Install Docker Compose
install_docker_compose() {
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        log_info "Docker Compose already available"
        return 0
    fi
    
    log_info "Installing Docker Compose..."
    apt-get install -y -qq docker-compose-plugin > /dev/null
    log_success "Docker Compose installed"
}

# Create fula user and group
create_user() {
    if id "${FULA_USER}" &>/dev/null; then
        log_info "User ${FULA_USER} already exists"
    else
        log_info "Creating user ${FULA_USER}..."
        groupadd -r ${FULA_GROUP} 2>/dev/null || true
        useradd -r -g ${FULA_GROUP} -d ${FULA_HOME} -s /bin/false ${FULA_USER}
        log_success "User ${FULA_USER} created"
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    mkdir -p ${FULA_HOME}/data
    mkdir -p ${FULA_CONFIG}
    mkdir -p ${FULA_LOG}
    
    chown -R ${FULA_USER}:${FULA_GROUP} ${FULA_HOME}
    chown -R ${FULA_USER}:${FULA_GROUP} ${FULA_CONFIG}
    chown -R ${FULA_USER}:${FULA_GROUP} ${FULA_LOG}
    
    chmod 750 ${FULA_HOME}
    chmod 750 ${FULA_CONFIG}
    chmod 750 ${FULA_LOG}
    
    log_success "Directories created"
}

# Load existing environment values
load_existing_env() {
    if [[ -f "${ENV_FILE}" ]]; then
        log_info "Found existing configuration at ${ENV_FILE}"
        source "${ENV_FILE}"
        return 0
    fi
    return 1
}

# Prompt for environment variable with default
prompt_env() {
    local var_name="$1"
    local prompt_text="$2"
    local default_value="$3"
    local is_secret="${4:-false}"
    
    local current_value="${!var_name:-$default_value}"
    
    if [[ "$is_secret" == "true" && -n "$current_value" && "$current_value" != "$default_value" ]]; then
        echo -n "${prompt_text} [****hidden****]: "
        read -r input
        if [[ -z "$input" ]]; then
            export "$var_name"="$current_value"
        else
            export "$var_name"="$input"
        fi
    else
        echo -n "${prompt_text} [${current_value}]: "
        read -r input
        export "$var_name"="${input:-$current_value}"
    fi
}

# Generate random secret
generate_secret() {
    openssl rand -base64 32 | tr -d '\n'
}

# Collect configuration
collect_configuration() {
    log_info "Configuring Fula Gateway..."
    echo ""
    echo "==========================================="
    echo "         Fula Gateway Configuration        "
    echo "==========================================="
    echo ""
    
    # Load existing values if available
    load_existing_env || true
    
    # Gateway domain
    prompt_env "FULA_DOMAIN" "Gateway domain (e.g., api.example.com)"  ""
    if [[ -z "${FULA_DOMAIN}" ]]; then
        log_error "Gateway domain is required"
        exit 1
    fi
    
    # IPFS domain (optional)
    echo ""
    log_info "IPFS Configuration"
    prompt_env "IPFS_DOMAIN" "IPFS RPC domain (leave empty to skip IPFS setup)" ""
    
    # Check if IPFS is already running
    IPFS_RUNNING=false
    if curl -s http://localhost:5001/api/v0/id > /dev/null 2>&1; then
        log_info "Detected running IPFS daemon on localhost:5001"
        IPFS_RUNNING=true
    fi
    
    # JWT Secret
    echo ""
    log_info "Authentication Configuration"
    DEFAULT_JWT_SECRET="${JWT_SECRET:-$(generate_secret)}"
    prompt_env "JWT_SECRET" "JWT Secret (auto-generated if empty)" "$DEFAULT_JWT_SECRET" true
    
    # OAuth settings
    prompt_env "OAUTH_ISSUER" "OAuth Issuer URL (optional)" "${OAUTH_ISSUER:-}"
    prompt_env "OAUTH_AUDIENCE" "OAuth Audience (optional)" "${OAUTH_AUDIENCE:-}"
    
    # CORS
    echo ""
    log_info "CORS Configuration"
    prompt_env "CORS_ORIGINS" "Allowed CORS origins (comma-separated, or * for all)" "${CORS_ORIGINS:-https://${FULA_DOMAIN}}"
    
    # Pinning service (optional)
    echo ""
    log_info "Pinning Service (optional)"
    prompt_env "PINNING_SERVICE_ENDPOINT" "Pinning service endpoint" "${PINNING_SERVICE_ENDPOINT:-}"
    if [[ -n "${PINNING_SERVICE_ENDPOINT}" ]]; then
        prompt_env "PINNING_SERVICE_TOKEN" "Pinning service token" "${PINNING_SERVICE_TOKEN:-}" true
    fi
    
    # Gateway port
    prompt_env "GATEWAY_PORT" "Gateway internal port" "${GATEWAY_PORT:-$DEFAULT_GATEWAY_PORT}"
    
    # Confirm
    echo ""
    echo "==========================================="
    echo "              Configuration Summary         "
    echo "==========================================="
    echo "Gateway Domain:    ${FULA_DOMAIN}"
    echo "IPFS Domain:       ${IPFS_DOMAIN:-Not configured}"
    echo "Gateway Port:      ${GATEWAY_PORT}"
    echo "CORS Origins:      ${CORS_ORIGINS}"
    echo "Auth Enabled:      Yes (always enabled)"
    echo "==========================================="
    echo ""
    
    read -p "Proceed with installation? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
}

# Write environment file
write_env_file() {
    log_info "Writing configuration..."
    
    cat > "${ENV_FILE}" << EOF
# Fula Gateway Configuration
# Generated on $(date)

# Domain Configuration
FULA_DOMAIN=${FULA_DOMAIN}
IPFS_DOMAIN=${IPFS_DOMAIN:-}

# Authentication (REQUIRED - auth is always enabled)
JWT_SECRET=${JWT_SECRET}
OAUTH_ISSUER=${OAUTH_ISSUER:-}
OAUTH_AUDIENCE=${OAUTH_AUDIENCE:-}

# CORS Configuration
CORS_ENABLED=true
CORS_ORIGINS=${CORS_ORIGINS}

# Gateway Settings
GATEWAY_PORT=${GATEWAY_PORT}
RUST_LOG=info,fula_cli=debug

# IPFS Configuration
IPFS_URL=http://localhost:5001

# Pinning Service (optional)
PINNING_SERVICE_ENDPOINT=${PINNING_SERVICE_ENDPOINT:-}
PINNING_SERVICE_TOKEN=${PINNING_SERVICE_TOKEN:-}
EOF

    chmod 640 "${ENV_FILE}"
    chown ${FULA_USER}:${FULA_GROUP} "${ENV_FILE}"
    
    log_success "Configuration written to ${ENV_FILE}"
}

# Create Docker Compose file
create_docker_compose() {
    log_info "Creating Docker Compose configuration..."
    
    local IPFS_SERVICE=""
    if [[ -n "${IPFS_DOMAIN}" ]] && [[ "${IPFS_RUNNING}" != "true" ]]; then
        IPFS_SERVICE="
  ipfs:
    image: ipfs/kubo:latest
    container_name: fula-ipfs
    restart: unless-stopped
    volumes:
      - ${FULA_HOME}/ipfs:/data/ipfs
    ports:
      - '127.0.0.1:5001:5001'
      - '127.0.0.1:8081:8080'
    environment:
      - IPFS_PROFILE=server
    healthcheck:
      test: ['CMD-SHELL', 'ipfs id || exit 1']
      interval: 30s
      timeout: 10s
      retries: 3
"
    fi
    
    cat > "${FULA_CONFIG}/docker-compose.yml" << EOF
version: '3.8'

services:
  gateway:
    image: ghcr.io/functionland/fula-gateway:latest
    container_name: fula-gateway
    restart: unless-stopped
    env_file:
      - ${ENV_FILE}
    volumes:
      - ${FULA_HOME}/data:/var/lib/fula/data
    ports:
      - '127.0.0.1:${GATEWAY_PORT}:${GATEWAY_PORT}'
    depends_on:
      ${IPFS_DOMAIN:+ipfs:}
      ${IPFS_DOMAIN:+  condition: service_healthy}
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:${GATEWAY_PORT}/']
      interval: 30s
      timeout: 10s
      retries: 3
${IPFS_SERVICE}
networks:
  default:
    name: fula-network
EOF

    chown ${FULA_USER}:${FULA_GROUP} "${FULA_CONFIG}/docker-compose.yml"
    
    log_success "Docker Compose configuration created"
}

# Configure Nginx
configure_nginx() {
    log_info "Configuring Nginx..."
    
    # Gateway nginx config
    cat > "${NGINX_CONF}" << EOF
# Fula Gateway - Rate Limiting
limit_req_zone \$binary_remote_addr zone=fula_limit:10m rate=100r/s;
limit_conn_zone \$binary_remote_addr zone=fula_conn:10m;

# Gateway Server
server {
    listen 80;
    listen [::]:80;
    server_name ${FULA_DOMAIN};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req zone=fula_limit burst=50 nodelay;
    limit_conn fula_conn 20;

    # Request size limit (for large uploads, adjust as needed)
    client_max_body_size 5G;
    client_body_timeout 3600s;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:${GATEWAY_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        
        # Buffering settings for large files
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Health check endpoint (no rate limit)
    location = /health {
        limit_req off;
        proxy_pass http://127.0.0.1:${GATEWAY_PORT}/;
    }
}
EOF

    # IPFS nginx config (if domain provided)
    if [[ -n "${IPFS_DOMAIN}" ]]; then
        cat > "/etc/nginx/sites-available/fula-ipfs" << EOF
# Fula IPFS Gateway
server {
    listen 80;
    listen [::]:80;
    server_name ${IPFS_DOMAIN};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Rate limiting for IPFS
    limit_req zone=fula_limit burst=20 nodelay;
    limit_conn fula_conn 10;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Block sensitive IPFS API endpoints
    location ~ ^/api/v0/(config|key|bootstrap|swarm/connect) {
        return 403;
    }
}
EOF
        ln -sf /etc/nginx/sites-available/fula-ipfs /etc/nginx/sites-enabled/
    fi

    # Enable site
    ln -sf "${NGINX_CONF}" "${NGINX_ENABLED}"
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx config
    nginx -t
    
    log_success "Nginx configured"
}

# Configure SSL with Certbot
configure_ssl() {
    log_info "Configuring SSL certificates..."
    
    # Gateway certificate
    certbot --nginx -d "${FULA_DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email || {
        log_warn "Certbot failed for ${FULA_DOMAIN}. You may need to run it manually."
    }
    
    # IPFS certificate
    if [[ -n "${IPFS_DOMAIN}" ]]; then
        certbot --nginx -d "${IPFS_DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email || {
            log_warn "Certbot failed for ${IPFS_DOMAIN}. You may need to run it manually."
        }
    fi
    
    # Setup auto-renewal
    systemctl enable certbot.timer
    systemctl start certbot.timer
    
    log_success "SSL configured"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow IPFS swarm if running local IPFS
    if [[ -n "${IPFS_DOMAIN}" ]] && [[ "${IPFS_RUNNING}" != "true" ]]; then
        ufw allow 4001/tcp  # IPFS swarm
    fi
    
    ufw --force enable
    
    log_success "Firewall configured"
}

# Configure fail2ban
configure_fail2ban() {
    log_info "Configuring fail2ban..."
    
    cat > /etc/fail2ban/jail.d/fula.conf << EOF
[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 3600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
findtime = 60
bantime = 3600
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "fail2ban configured"
}

# Create systemd service for Docker Compose
create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/fula-gateway.service << EOF
[Unit]
Description=Fula Gateway (Docker Compose)
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=${FULA_CONFIG}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fula-gateway
    
    log_success "Systemd service created"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    systemctl restart nginx
    systemctl start fula-gateway
    
    # Wait for services to start
    sleep 5
    
    log_success "Services started"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    local errors=0
    
    # Check nginx
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running"
        ((errors++))
    fi
    
    # Check Docker containers
    if docker ps | grep -q fula-gateway; then
        log_success "Gateway container is running"
    else
        log_warn "Gateway container not yet running (may be pulling image)"
    fi
    
    # Check gateway health (via localhost)
    sleep 10
    if curl -s http://localhost:${GATEWAY_PORT}/ > /dev/null 2>&1; then
        log_success "Gateway responding on localhost:${GATEWAY_PORT}"
    else
        log_warn "Gateway not responding yet (may still be starting)"
    fi
    
    # Check SSL
    if [[ -f "/etc/letsencrypt/live/${FULA_DOMAIN}/fullchain.pem" ]]; then
        log_success "SSL certificate installed for ${FULA_DOMAIN}"
    else
        log_warn "SSL certificate not found - run certbot manually if needed"
    fi
    
    # Print summary
    echo ""
    echo "==========================================="
    echo "         Installation Complete!            "
    echo "==========================================="
    echo ""
    echo "Gateway URL:     https://${FULA_DOMAIN}"
    if [[ -n "${IPFS_DOMAIN}" ]]; then
        echo "IPFS Gateway:    https://${IPFS_DOMAIN}"
    fi
    echo ""
    echo "Configuration:   ${ENV_FILE}"
    echo "Logs:            docker compose -f ${FULA_CONFIG}/docker-compose.yml logs -f"
    echo ""
    echo "Commands:"
    echo "  Start:         systemctl start fula-gateway"
    echo "  Stop:          systemctl stop fula-gateway"
    echo "  Restart:       systemctl restart fula-gateway"
    echo "  Status:        systemctl status fula-gateway"
    echo "  Logs:          journalctl -u fula-gateway -f"
    echo ""
    
    if [[ ! "${IPFS_RUNNING}" == "true" ]] && [[ -z "${IPFS_DOMAIN}" ]]; then
        log_warn "IPFS is not running and no IPFS domain was configured."
        log_warn "The gateway will use in-memory storage (data will not persist)."
        log_warn "To enable persistence, either:"
        log_warn "  1. Install and run IPFS locally"
        log_warn "  2. Re-run this script with an IPFS domain"
    fi
    
    echo "==========================================="
    
    if [[ $errors -gt 0 ]]; then
        log_error "Installation completed with $errors errors"
        return 1
    fi
    
    return 0
}

# Main installation flow
main() {
    echo ""
    echo "==========================================="
    echo "      Fula Gateway Installation Script     "
    echo "==========================================="
    echo ""
    
    check_root
    check_os
    
    install_dependencies
    install_docker
    install_docker_compose
    
    create_user
    create_directories
    
    collect_configuration
    write_env_file
    
    create_docker_compose
    configure_nginx
    configure_ssl
    configure_firewall
    configure_fail2ban
    create_systemd_service
    
    start_services
    verify_installation
    
    log_success "Installation complete!"
}

# Run main function
main "$@"
