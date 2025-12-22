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

# Default values (must match Dockerfile defaults)
DEFAULT_GATEWAY_PORT="9000"
DEFAULT_IPFS_PORT="5001"
DEFAULT_IPFS_GATEWAY_PORT="8081"
DEFAULT_MAX_BODY_SIZE="5368709120"  # 5GB
DEFAULT_RATE_LIMIT_RPS="100"
DEFAULT_REQUEST_TIMEOUT="3600"  # 1 hour for large uploads

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
        git \
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

    # Ubuntu 24.04+ uses Docker Compose v2 as a plugin
    # Try installing via apt first (for older Ubuntu versions)
    if apt-get install -y -qq docker-compose-plugin > /dev/null 2>&1; then
        log_success "Docker Compose installed via apt"
        return 0
    fi

    # If apt install failed, try manual installation
    log_info "Installing Docker Compose manually..."
    local COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$COMPOSE_VERSION" ]]; then
        COMPOSE_VERSION="v2.29.1"  # fallback version
    fi

    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    if docker-compose version &> /dev/null; then
        log_success "Docker Compose installed manually"
    else
        log_error "Failed to install Docker Compose"
        return 1
    fi
}

# Clone or update source code
clone_source() {
    local SOURCE_DIR="/opt/fula-api"
    local REPO_URL="https://github.com/functionland/fula-api.git"
    
    if [[ -d "${SOURCE_DIR}" ]]; then
        log_info "Updating source code in ${SOURCE_DIR}..."
        cd "${SOURCE_DIR}"
        git fetch origin main --depth=1 2>/dev/null || true
        git reset --hard origin/main 2>/dev/null || true
        cd - > /dev/null
    else
        log_info "Cloning source code to ${SOURCE_DIR}..."
        git clone --depth=1 "${REPO_URL}" "${SOURCE_DIR}"
    fi
    
    log_success "Source code ready at ${SOURCE_DIR}"
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
        if [[ -z "${PINNING_SERVICE_TOKEN}" ]]; then
            log_warn "Pinning service endpoint provided without token - SERVER-LEVEL pinning will be DISABLED"
            log_warn "Users can still pin via per-request headers (X-Pinning-Service, X-Pinning-Token)"
        fi
    fi
    
    # Gateway port
    prompt_env "GATEWAY_PORT" "Gateway internal port" "${GATEWAY_PORT:-$DEFAULT_GATEWAY_PORT}"
    
    # Performance settings
    echo ""
    log_info "Performance Settings"
    prompt_env "MAX_BODY_SIZE" "Max upload size in bytes (default 5GB)" "${MAX_BODY_SIZE:-$DEFAULT_MAX_BODY_SIZE}"
    prompt_env "RATE_LIMIT_RPS" "Rate limit requests per second" "${RATE_LIMIT_RPS:-$DEFAULT_RATE_LIMIT_RPS}"
    prompt_env "REQUEST_TIMEOUT" "Request timeout in seconds" "${REQUEST_TIMEOUT:-$DEFAULT_REQUEST_TIMEOUT}"
    
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

# CORS Configuration
CORS_ENABLED=true
CORS_ORIGINS=${CORS_ORIGINS}

# Gateway Settings (FULA_PORT must match Dockerfile)
FULA_HOST=0.0.0.0
FULA_PORT=${GATEWAY_PORT}
RUST_LOG=info,fula_cli=debug,fula_core=debug

# Performance Settings
MAX_BODY_SIZE=${MAX_BODY_SIZE}
RATE_LIMIT_RPS=${RATE_LIMIT_RPS}
REQUEST_TIMEOUT=${REQUEST_TIMEOUT}

# IPFS Configuration
IPFS_URL=http://localhost:5001

# Pinning Service (optional - gateway-level pinning for all uploads)
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

    cat > "${FULA_CONFIG}/docker-compose.yml" << EOF
# Fula Storage - Complete Development Stack
# Run with: docker-compose up -d

version: "3.8"

services:
  # ============================================
  # Fula Gateway - S3-Compatible API
  # ============================================
  gateway:
    build:
      context: /opt/fula-api
      dockerfile: Dockerfile
    environment:
      - FULA_HOST=0.0.0.0
      - FULA_PORT=${GATEWAY_PORT}
      - IPFS_API_URL=http://localhost:5001
      - CLUSTER_API_URL=http://localhost:9094
      - JWT_SECRET=\${JWT_SECRET:-development-secret-change-in-production}
      - FULA_NO_AUTH=\${FULA_NO_AUTH:-false}
      - RUST_LOG=info,fula_cli=debug
    volumes:
      - gateway-data:/var/lib/fula-gateway
    network_mode: host
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${GATEWAY_PORT}/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

  # ============================================
  # Redis (optional - for multi-gateway sync)
  # ============================================
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped
    networks:
      - fula-network
    profiles:
      - full

  # ============================================
  # Prometheus (optional - monitoring)
  # ============================================
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
    restart: unless-stopped
    networks:
      - fula-network
    profiles:
      - monitoring

  # ============================================
  # Grafana (optional - dashboards)
  # ============================================
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=\${GRAFANA_PASSWORD:-admin}
    depends_on:
      - prometheus
    restart: unless-stopped
    networks:
      - fula-network
    profiles:
      - monitoring

# ============================================
# Networks
# ============================================
networks:
  fula-network:
    driver: bridge

# ============================================
# Volumes
# ============================================
volumes:
  gateway-data:
  redis-data:
  prometheus-data:
  grafana-data:
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
limit_req_zone \$binary_remote_addr zone=fula_limit:10m rate=${RATE_LIMIT_RPS}r/s;
limit_conn_zone \$binary_remote_addr zone=fula_conn:10m;

# Upstream with keepalive connections
upstream fula_gateway {
    server 127.0.0.1:${GATEWAY_PORT};
    keepalive 32;
}

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
    add_header Content-Security-Policy "default-src 'self'" always;

    # Rate limiting
    limit_req zone=fula_limit burst=50 nodelay;
    limit_conn fula_conn 20;

    # Request size limit (for large uploads)
    client_max_body_size 5G;
    client_body_timeout ${REQUEST_TIMEOUT}s;
    proxy_read_timeout ${REQUEST_TIMEOUT}s;
    proxy_send_timeout ${REQUEST_TIMEOUT}s;
    send_timeout ${REQUEST_TIMEOUT}s;
    
    # Increase buffer sizes for S3 clients that send many headers
    proxy_buffer_size 16k;
    proxy_buffers 4 32k;
    proxy_busy_buffers_size 64k;
    large_client_header_buffers 4 32k;

    location / {
        proxy_pass http://fula_gateway;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        
        # Disable buffering for streaming uploads/downloads
        proxy_buffering off;
        proxy_request_buffering off;
        
        # Pass through all S3 headers
        proxy_pass_request_headers on;
    }

    # Health check endpoint (efficient HEAD request)
    location = /_health {
        proxy_pass http://fula_gateway/;
        proxy_method HEAD;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
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
    log_info "Configuring SSL certificate for gateway..."
    
    # Gateway certificate only - IPFS and pinning endpoints are external services
    # with their own SSL already configured by the user
    certbot --nginx -d "${FULA_DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email || {
        log_warn "Certbot failed for ${FULA_DOMAIN}. You may need to run it manually."
    }
    
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
        ufw allow 4001/tcp   # IPFS swarm TCP
        ufw allow 4001/udp   # IPFS swarm QUIC
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

    # Detect which Docker Compose version is installed
    local COMPOSE_CMD
    if docker compose version &> /dev/null; then
        # Docker Compose v2 (plugin)
        COMPOSE_CMD="/usr/bin/docker compose"
    elif command -v docker-compose &> /dev/null; then
        # Docker Compose v1 (standalone)
        COMPOSE_CMD="/usr/local/bin/docker-compose"
    else
        log_error "No Docker Compose installation found"
        return 1
    fi

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
ExecStart=${COMPOSE_CMD} up -d
ExecStop=${COMPOSE_CMD} down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fula-gateway

    log_success "Systemd service created"
}

# Configure IPFS settings for optimal performance
configure_ipfs_settings() {
    if [[ -z "${IPFS_DOMAIN}" ]] && [[ "${IPFS_RUNNING}" != "true" ]]; then
        return 0
    fi
    
    log_info "Configuring IPFS settings..."
    
    # Wait for IPFS to be ready
    local retries=30
    while ! curl -s http://localhost:5001/api/v0/id > /dev/null 2>&1; do
        retries=$((retries - 1))
        if [[ $retries -eq 0 ]]; then
            log_warn "IPFS not responding, skipping configuration"
            return 0
        fi
        sleep 2
    done
    
    # Configure IPFS for production
    # Increase connection limits
    curl -s -X POST "http://localhost:5001/api/v0/config?arg=Swarm.ConnMgr.LowWater&arg=100&json=true" > /dev/null
    curl -s -X POST "http://localhost:5001/api/v0/config?arg=Swarm.ConnMgr.HighWater&arg=400&json=true" > /dev/null
    curl -s -X POST "http://localhost:5001/api/v0/config?arg=Swarm.ConnMgr.GracePeriod&arg=60s&json=true" > /dev/null
    
    # Enable QUIC transport
    curl -s -X POST "http://localhost:5001/api/v0/config?arg=Swarm.Transports.Network.QUIC&arg=true&json=true" > /dev/null
    
    # Increase API timeout for large operations
    curl -s -X POST "http://localhost:5001/api/v0/config?arg=API.HTTPHeaders.Access-Control-Allow-Origin&arg=[\"*\"]&json=true" > /dev/null
    
    log_success "IPFS configured for production"
}

# Build Docker image
build_docker_image() {
    log_info "Building Docker image (this may take 5-15 minutes on first run)..."
    
    cd "${FULA_CONFIG}"
    
    # Build with visible output so user can see any errors
    if ! docker compose build --progress=plain gateway 2>&1 | tee /tmp/fula-build.log; then
        log_error "Docker build failed. Check /tmp/fula-build.log for details"
        log_error "Common fixes:"
        log_error "  - Ensure server has at least 4GB RAM for Rust compilation"
        log_error "  - Try: CARGO_BUILD_JOBS=1 docker compose build gateway"
        return 1
    fi
    
    log_success "Docker image built successfully"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Build the Docker image first (with visible output)
    build_docker_image || {
        log_error "Cannot start services - Docker build failed"
        return 1
    }
    
    systemctl restart nginx
    systemctl start fula-gateway
    
    # Wait for services to start
    sleep 5
    
    # Configure IPFS if running
    configure_ipfs_settings
    
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
    
    # Check gateway health (via localhost) using HEAD request
    sleep 10
    if curl -s -X HEAD -o /dev/null -w "%{http_code}" http://localhost:${GATEWAY_PORT}/ | grep -q "200"; then
        log_success "Gateway responding on localhost:${GATEWAY_PORT}"
    else
        log_warn "Gateway not responding yet (may still be starting)"
        log_info "Check logs: docker compose -f ${FULA_CONFIG}/docker-compose.yml logs gateway"
    fi
    
    # Check IPFS if configured
    if [[ -n "${IPFS_DOMAIN}" ]] || [[ "${IPFS_RUNNING}" == "true" ]]; then
        if curl -s http://localhost:5001/api/v0/id > /dev/null 2>&1; then
            log_success "IPFS daemon responding on localhost:5001"
        else
            log_warn "IPFS daemon not responding"
        fi
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
    echo "  Logs:          docker compose -f ${FULA_CONFIG}/docker-compose.yml logs -f"
    echo ""
    echo "Configuration files:"
    echo "  Environment:   ${ENV_FILE}"
    echo "  Docker:        ${FULA_CONFIG}/docker-compose.yml"
    echo "  Nginx:         ${NGINX_CONF}"
    echo ""
    
    if [[ ! "${IPFS_RUNNING}" == "true" ]] && [[ -z "${IPFS_DOMAIN}" ]]; then
        log_warn "IPFS is not running and no IPFS domain was configured."
        log_warn "The gateway will use in-memory storage (data will not persist)."
        log_warn "To enable persistence, either:"
        log_warn "  1. Install and run IPFS locally"
        log_warn "  2. Re-run this script with an IPFS domain"
    fi
    
    echo ""
    echo "Troubleshooting:"
    echo "  View gateway logs:  docker compose -f ${FULA_CONFIG}/docker-compose.yml logs gateway"
    echo "  View IPFS logs:     docker compose -f ${FULA_CONFIG}/docker-compose.yml logs ipfs"
    echo "  Test health:        curl -I https://${FULA_DOMAIN}/"
    echo "  Rebuild image:      cd /opt/fula-api && git pull && docker compose -f ${FULA_CONFIG}/docker-compose.yml build gateway"
    echo ""
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
    clone_source
    
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
