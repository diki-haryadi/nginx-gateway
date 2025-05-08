#!/bin/bash

# Configuration variables
NGINX_CONFIG_DIR="/etc/nginx"
NGINX_SITES_AVAILABLE="$NGINX_CONFIG_DIR/sites-available"
NGINX_SITES_ENABLED="$NGINX_CONFIG_DIR/sites-enabled"
LOG_FILE="/var/log/nginx_domain_setup.log"
BACKUP_DIR="/var/backup/nginx_config"

# Function to log messages
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Function to check if script is run as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR: This script must be run as root"
        exit 1
    fi
}

# Function to check OS compatibility
check_os() {
    if [ -f /etc/debian_version ]; then
        log_message "Detected Debian-based OS"
    elif [ -f /etc/redhat-release ]; then
        log_message "Detected Red Hat-based OS"
        log_message "NOTE: This script is optimized for Debian-based systems, some commands may need adjustment"
    else
        log_message "WARNING: Unsupported operating system. This script is designed for Debian-based systems."
    fi
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to validate IP address
validate_ip() {
    local ip="$1"
    if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_message "ERROR: Invalid IP address format: $ip"
        return 1
    fi
    return 0
}

# Function to validate port number
validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_message "ERROR: Invalid port number: $port"
        return 1
    fi
    return 0
}

# Function to validate domain name
validate_domain() {
    local domain="$1"
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$ ]]; then
        log_message "ERROR: Invalid domain name format: $domain"
        return 1
    fi
    return 0
}

# Function to validate email address
validate_email() {
    local email="$1"
    if [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_message "ERROR: Invalid email address format: $email"
        return 1
    fi
    return 0
}

# Function to create backup of Nginx configuration
backup_config() {
    local timestamp=$(date "+%Y%m%d%H%M%S")
    local backup_path="$BACKUP_DIR/nginx_config_$timestamp"
    
    log_message "Creating backup of current Nginx configuration..."
    
    mkdir -p "$BACKUP_DIR"
    
    if [ -d "$NGINX_CONFIG_DIR" ]; then
        cp -r "$NGINX_CONFIG_DIR" "$backup_path"
        log_message "Backup created at $backup_path"
    else
        log_message "WARNING: Nginx configuration directory not found, no backup created"
    fi
}

# Function to install Nginx and Certbot
install_dependencies() {
    log_message "Checking and installing dependencies..."
    
    if ! command_exists nginx; then
        log_message "Installing Nginx..."
        apt-get update || { log_message "ERROR: Failed to update package lists"; exit 1; }
        apt-get install -y nginx || { log_message "ERROR: Failed to install Nginx"; exit 1; }
    else
        log_message "Nginx is already installed."
    fi
    
    if ! command_exists certbot; then
        log_message "Installing Certbot..."
        apt-get update || { log_message "ERROR: Failed to update package lists"; exit 1; }
        apt-get install -y certbot python3-certbot-nginx || { log_message "ERROR: Failed to install Certbot"; exit 1; }
    else
        log_message "Certbot is already installed."
    fi
}

# Function to create Nginx configuration for a domain
create_nginx_config() {
    local domain="$1"
    local target_ip="$2"
    local target_port="$3"
    
    log_message "Creating Nginx configuration for $domain..."
    
    # Create the configuration file
    cat > "$NGINX_SITES_AVAILABLE/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    location / {
        proxy_pass http://$target_ip:$target_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF
    
    # Enable the site
    ln -sf "$NGINX_SITES_AVAILABLE/$domain.conf" "$NGINX_SITES_ENABLED/"
    
    log_message "Nginx configuration for $domain created and enabled."
}

# Function to obtain SSL certificates using Certbot
setup_ssl() {
    local domain="$1"
    local email="$2"
    
    if [ -z "$email" ]; then
        email="admin@$domain"
    fi
    
    validate_email "$email" || {
        log_message "Using default email: admin@$domain"
        email="admin@$domain"
    }
    
    log_message "Setting up SSL for $domain using Certbot..."
    
    # Obtain and install the SSL certificate
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email "$email" --redirect || {
        log_message "ERROR: Failed to obtain SSL certificate for $domain"
        return 1
    }
    
    log_message "SSL setup completed for $domain."
    return 0
}

# Function to generate a self-signed certificate
generate_self_signed_ssl() {
    local domain="$1"
    
    log_message "Generating self-signed SSL certificate for $domain..."
    
    # Create directory for certificates if it doesn't exist
    mkdir -p "/etc/nginx/ssl/$domain"
    
    # Generate private key and certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "/etc/nginx/ssl/$domain/privkey.pem" \
        -out "/etc/nginx/ssl/$domain/fullchain.pem" \
        -subj "/CN=$domain" || {
        log_message "ERROR: Failed to generate self-signed certificate for $domain"
        return 1
    }
    
    # Update Nginx configuration to use the self-signed certificate
    sed -i "/server_name $domain;/a \\\n    ssl_certificate /etc/nginx/ssl/$domain/fullchain.pem;\n    ssl_certificate_key /etc/nginx/ssl/$domain/privkey.pem;\n    ssl on;" "$NGINX_SITES_AVAILABLE/$domain.conf"
    
    # Update configuration to listen on port 443
    sed -i "s/listen 80;/listen 80;\n    listen 443 ssl;/" "$NGINX_SITES_AVAILABLE/$domain.conf"
    
    log_message "Self-signed SSL certificate generated and configured for $domain."
    return 0
}

# Function to test if a service is reachable
test_service() {
    local ip="$1"
    local port="$2"
    
    log_message "Testing connectivity to $ip:$port..."
    
    if command_exists nc; then
        timeout 5 nc -z "$ip" "$port" &>/dev/null
        if [ $? -eq 0 ]; then
            log_message "Service at $ip:$port is reachable."
            return 0
        else
            log_message "WARNING: Service at $ip:$port is not reachable. Nginx will proxy to this address, but it may not work."
            return 1
        fi
    else
        log_message "WARNING: 'nc' command not available. Cannot test service connectivity."
        return 0
    fi
}

# Function to add a new domain
add_domain() {
    local domain="$1"
    local target_ip="$2"
    local target_port="$3"
    local email="$4"
    local ssl_type="${5:-self-signed}"  # Default to self-signed
    
    # Validate inputs
    validate_domain "$domain" || return 1
    validate_ip "$target_ip" || return 1
    validate_port "$target_port" || return 1
    
    log_message "Adding new domain: $domain -> $target_ip:$target_port (SSL type: $ssl_type)"
    
    # Test if the target service is reachable
    test_service "$target_ip" "$target_port"
    
    # Create Nginx configuration
    create_nginx_config "$domain" "$target_ip" "$target_port"
    
    # Test Nginx configuration
    nginx -t
    
    if [ $? -eq 0 ]; then
        # Reload Nginx to apply changes
        systemctl reload nginx || {
            log_message "ERROR: Failed to reload Nginx"
            return 1
        }
        
        # Setup SSL based on type
        if [ "$ssl_type" = "letsencrypt" ]; then
            setup_ssl "$domain" "$email"
        else
            generate_self_signed_ssl "$domain"
        fi
        
        # Reload Nginx again after SSL setup
        nginx -t && systemctl reload nginx
        
        log_message "Domain $domain has been successfully added."
        return 0
    else
        log_message "ERROR: Nginx configuration test failed. Domain $domain was not added."
        return 1
    fi
}

# Function for interactive input
get_interactive_input() {
    local prompt="$1"
    local variable_name="$2"
    local validation_function="$3"
    local value
    
    while true; do
        read -p "$prompt: " value
        
        if [ -n "$validation_function" ]; then
            $validation_function "$value"
            if [ $? -eq 0 ]; then
                break
            fi
        else
            break
        fi
    done
    
    eval "$variable_name=\"$value\""
}

# Function for initial setup
initial_setup() {
    log_message "Starting initial setup..."
    
    # Install required dependencies
    install_dependencies
    
    # Create directories if they don't exist
    mkdir -p "$NGINX_SITES_AVAILABLE"
    mkdir -p "$NGINX_SITES_ENABLED"
    mkdir -p "/etc/nginx/ssl"
    
    # Backup existing configuration
    backup_config
    
    # Ask for admin email
    get_interactive_input "Enter admin email for SSL certificates" admin_email validate_email
    
    # Ask for SSL type
    get_interactive_input "SSL type (letsencrypt or self-signed)" ssl_type
    if [ "$ssl_type" != "letsencrypt" ] && [ "$ssl_type" != "self-signed" ]; then
        log_message "Invalid SSL type. Defaulting to self-signed."
        ssl_type="self-signed"
    fi
    
    # Get the number of domains to add
    get_interactive_input "Enter the number of domains to configure" num_domains
    
    for ((i=1; i<=num_domains; i++)); do
        get_interactive_input "Enter domain #$i" domain validate_domain
        get_interactive_input "Enter target IP for $domain" target_ip validate_ip
        get_interactive_input "Enter target port for $domain" target_port validate_port
        
        add_domain "$domain" "$target_ip" "$target_port" "$admin_email" "$ssl_type"
    done
    
    log_message "Initial setup completed."
}

# Function for non-interactive setup from a config file
setup_from_config() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        log_message "ERROR: Config file not found: $config_file"
        exit 1
    fi
    
    log_message "Setting up from config file: $config_file"
    
    # Install required dependencies
    install_dependencies
    
    # Create directories if they don't exist
    mkdir -p "$NGINX_SITES_AVAILABLE"
    mkdir -p "$NGINX_SITES_ENABLED"
    mkdir -p "/etc/nginx/ssl"
    
    # Backup existing configuration
    backup_config
    
    # Read the config file
    local admin_email
    local ssl_type
    
    admin_email=$(grep "^admin_email=" "$config_file" | cut -d= -f2)
    ssl_type=$(grep "^ssl_type=" "$config_file" | cut -d= -f2)
    
    if [ -z "$ssl_type" ] || ([ "$ssl_type" != "letsencrypt" ] && [ "$ssl_type" != "self-signed" ]); then
        log_message "Invalid or missing SSL type. Defaulting to self-signed."
        ssl_type="self-signed"
    fi
    
    while IFS=, read -r domain target_ip target_port; do
        if [ -n "$domain" ] && [ -n "$target_ip" ] && [ -n "$target_port" ]; then
            add_domain "$domain" "$target_ip" "$target_port" "$admin_email" "$ssl_type"
        fi
    done < <(grep -v "^admin_email=" "$config_file" | grep -v "^ssl_type=" "$config_file" | grep -v "^#")
    
    log_message "Setup from config file completed."
}

# Function to display help message
show_help() {
    echo "Nginx and SSL Domain Setup Script"
    echo
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Options:"
    echo "  --initial-setup        Perform interactive initial setup"
    echo "  --add-domain DOMAIN IP PORT [EMAIL] [SSL_TYPE]"
    echo "                         Add a new domain with the specified details"
    echo "                         SSL_TYPE can be 'letsencrypt' or 'self-signed'"
    echo "  --from-config FILE     Setup domains from a configuration file"
    echo "  --help                 Display this help message"
    echo
    echo "Examples:"
    echo "  $0 --initial-setup"
    echo "  $0 --add-domain example.com 192.168.1.100 8080 admin@example.com self-signed"
    echo "  $0 --from-config domains.conf"
    echo
    echo "Configuration file format:"
    echo "  admin_email=admin@example.com"
    echo "  ssl_type=self-signed"
    echo "  # Lines starting with # are comments"
    echo "  example.com,192.168.1.100,8080"
    echo "  example.org,192.168.1.100,8081"
}

# Main script logic
check_root
check_os

case "$1" in
    --add-domain)
        if [ "$#" -lt 4 ]; then
            log_message "ERROR: Missing arguments for --add-domain"
            show_help
            exit 1
        fi
        add_domain "$2" "$3" "$4" "${5:-}" "${6:-self-signed}"
        ;;
    --initial-setup)
        initial_setup
        ;;
    --from-config)
        if [ "$#" -ne 2 ]; then
            log_message "ERROR: Missing config file for --from-config"
            show_help
            exit 1
        fi
        setup_from_config "$2"
        ;;
    --help)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac