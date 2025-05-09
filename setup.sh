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
    
    # Install OpenSSL if not already installed
    if ! command_exists openssl; then
        log_message "Installing OpenSSL..."
        apt-get update || { log_message "ERROR: Failed to update package lists"; exit 1; }
        apt-get install -y openssl || { log_message "ERROR: Failed to install OpenSSL"; exit 1; }
    else
        log_message "OpenSSL is already installed."
    fi
    
    # Check for curl (needed for Cloudflare API)
    if ! command_exists curl; then
        log_message "Installing curl..."
        apt-get update || { log_message "ERROR: Failed to update package lists"; exit 1; }
        apt-get install -y curl || { log_message "ERROR: Failed to install curl"; exit 1; }
    else
        log_message "curl is already installed."
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
    
    # Verify the configuration file was created
    if [ ! -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        log_message "ERROR: Failed to create Nginx configuration file for $domain"
        return 1
    fi
    
    return 0
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
    
    # Make sure the domain is accessible over HTTP first
    log_message "Checking if domain is accessible before requesting certificate..."
    
    # Check if nginx is running
    if ! systemctl is-active --quiet nginx; then
        log_message "WARNING: Nginx is not running. Starting Nginx service..."
        systemctl start nginx
    fi
    
    # Try to obtain and install the SSL certificate
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email "$email" --redirect || {
        log_message "ERROR: Failed to obtain SSL certificate for $domain"
        log_message "This could be due to DNS not pointing to this server or rate limits with Let's Encrypt."
        log_message "Attempting to use --dry-run to diagnose the issue..."
        
        certbot --nginx -d "$domain" --non-interactive --agree-tos --email "$email" --redirect --dry-run
        
        log_message "Would you like to proceed with a self-signed certificate instead? (y/n)"
        read -p "Enter your choice (y/n): " fallback_choice
        
        if [ "$fallback_choice" = "y" ] || [ "$fallback_choice" = "Y" ]; then
            log_message "Falling back to self-signed certificate..."
            generate_self_signed_ssl "$domain"
            return $?
        else
            log_message "Certificate setup aborted."
            return 1
        fi
    }
    
    # Verify that SSL certificate was actually installed
    if grep -q "ssl_certificate" "$NGINX_SITES_AVAILABLE/$domain.conf"; then
        log_message "SSL setup completed for $domain with Let's Encrypt."
        return 0
    else
        log_message "WARNING: Let's Encrypt certificate may not have been installed correctly."
        log_message "Checking certbot certificates..."
        certbot certificates
        
        log_message "Would you like to force a self-signed certificate instead? (y/n)"
        read -p "Enter your choice (y/n): " fallback_choice
        
        if [ "$fallback_choice" = "y" ] || [ "$fallback_choice" = "Y" ]; then
            log_message "Setting up self-signed certificate as fallback..."
            generate_self_signed_ssl "$domain"
            return $?
        else
            log_message "Please check the Nginx configuration and certbot logs."
            return 1
        fi
    fi
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
        -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" || {
        log_message "ERROR: Failed to generate self-signed certificate for $domain"
        return 1
    }
    
    # Set proper permissions
    chmod 644 "/etc/nginx/ssl/$domain/fullchain.pem"
    chmod 600 "/etc/nginx/ssl/$domain/privkey.pem"
    
    # Create a completely new SSL-enabled configuration
    cat > "$NGINX_SITES_AVAILABLE/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    
    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name $domain;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/$domain/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        proxy_pass http://127.0.0.1:8080;
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
    
    log_message "Self-signed SSL certificate generated and configured for $domain."
    
    # Verify the configuration was created properly
    if [ -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        log_message "Verifying SSL configuration exists in the Nginx config file..."
        if grep -q "ssl_certificate" "$NGINX_SITES_AVAILABLE/$domain.conf"; then
            log_message "SSL configuration verified successfully."
            return 0
        else
            log_message "ERROR: SSL configuration not found in the Nginx config file."
            return 1
        fi
    else
        log_message "ERROR: Nginx configuration file not found."
        return 1
    fi
}

# Function to setup Cloudflare Origin Certificate
setup_cloudflare_origin_cert() {
    local domain="$1"
    local target_ip="$2"
    local target_port="$3"
    
    log_message "Setting up Cloudflare Origin Certificate for $domain..."
    
    # Create directories for certificates
    mkdir -p "/etc/nginx/ssl/$domain"
    
    # Ask for Cloudflare API credentials
    log_message "To generate a Cloudflare Origin Certificate, you need Cloudflare API credentials."
    log_message "You can create an API token in your Cloudflare dashboard under 'API Tokens'."
    log_message "The token needs permission for 'Zone:SSL and Certificates:Edit'."
    
    # Prompt for Cloudflare credentials
    read -p "Enter your Cloudflare email: " cf_email
    read -sp "Enter your Cloudflare API key (Global API Key): " cf_api_key
    echo
    
    # Create a CSR and private key
    log_message "Creating CSR and private key..."
    openssl req -new -newkey rsa:2048 -nodes -keyout "/etc/nginx/ssl/$domain/privkey.pem" \
        -out "/etc/nginx/ssl/$domain/csr.pem" -subj "/CN=$domain" || {
        log_message "ERROR: Failed to create CSR and private key"
        return 1
    }
    
    # Read the CSR content
    local csr_content=$(cat "/etc/nginx/ssl/$domain/csr.pem" | sed ':a;N;$!ba;s/\n/\\n/g')
    
    # Create request body for Cloudflare API
    local request_body="{\"hostnames\":[\"$domain\",\"*.$domain\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"csr\":\"$csr_content\"}"
    
    # Make request to Cloudflare API
    log_message "Requesting Cloudflare Origin Certificate..."
    local response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
        -H "X-Auth-Email: $cf_email" \
        -H "X-Auth-Key: $cf_api_key" \
        -H "Content-Type: application/json" \
        --data "$request_body")
    
    # Check if request was successful
    if echo "$response" | grep -q '"success":true'; then
        # Extract the certificate
        local cert=$(echo "$response" | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g')
        
        # Save the certificate
        echo "$cert" > "/etc/nginx/ssl/$domain/fullchain.pem"
        
        log_message "Cloudflare Origin Certificate obtained successfully."
        
        # Create Nginx configuration
        cat > "$NGINX_SITES_AVAILABLE/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    
    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name $domain;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/$domain/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
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
        
        # Test and reload Nginx
        if nginx -t; then
            systemctl reload nginx
            log_message "Cloudflare Origin Certificate setup completed for $domain."
            log_message "IMPORTANT: Make sure your domain's DNS is managed by Cloudflare"
            log_message "and the Cloudflare proxy (orange cloud) is enabled."
            return 0
        else
            log_message "ERROR: Nginx configuration test failed after setting up Cloudflare Origin Certificate."
            return 1
        fi
    else
        log_message "ERROR: Failed to obtain Cloudflare Origin Certificate."
        log_message "Response from Cloudflare API: $response"
        return 1
    fi
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
    
    # Handle different SSL types
    case "$ssl_type" in
        "letsencrypt")
            # For LetsEncrypt, first create the HTTP config, then obtain the certificate
            create_nginx_config "$domain" "$target_ip" "$target_port"
            
            # Enable the site if not already enabled
            if [ ! -L "$NGINX_SITES_ENABLED/$domain.conf" ]; then
                ln -sf "$NGINX_SITES_AVAILABLE/$domain.conf" "$NGINX_SITES_ENABLED/"
            fi
            
            # Test and reload Nginx configuration
            if nginx -t; then
                systemctl reload nginx
                
                # Setup LetsEncrypt SSL
                setup_ssl "$domain" "$email"
            else
                log_message "ERROR: Nginx configuration test failed. Domain $domain was not added."
                return 1
            fi
            ;;
            
        "cloudflare")
            # Setup Cloudflare Origin Certificate
            setup_cloudflare_origin_cert "$domain" "$target_ip" "$target_port"
            ;;
            
        *)  # Default to self-signed
            log_message "Using self-signed SSL, generating certificate and creating combined configuration..."
            generate_self_signed_ssl "$domain"
            
            # Update the target IP and port in the config
            sed -i "s|proxy_pass http://127.0.0.1:8080;|proxy_pass http://$target_ip:$target_port;|" "$NGINX_SITES_AVAILABLE/$domain.conf"
            
            # Enable the site if not already enabled
            if [ ! -L "$NGINX_SITES_ENABLED/$domain.conf" ]; then
                ln -sf "$NGINX_SITES_AVAILABLE/$domain.conf" "$NGINX_SITES_ENABLED/"
            fi
            
            # Test and reload Nginx configuration
            if nginx -t; then
                systemctl reload nginx
                log_message "Self-signed SSL certificate setup completed."
            else
                log_message "ERROR: Nginx configuration test failed. Domain $domain was not added."
                return 1
            fi
            ;;
    esac
    
    # Final verification and logging
    if nginx -t; then
        log_message "Domain $domain has been successfully added with $ssl_type SSL."
        log_message "Configuration saved to: $NGINX_SITES_AVAILABLE/$domain.conf"
        
        # Provide browser security warning information for self-signed certificates
        if [ "$ssl_type" = "self-signed" ]; then
            log_message "IMPORTANT: Self-signed certificates will show as 'Not Secure' in browsers."
            log_message "This is normal behavior as browsers don't trust self-signed certificates."
            log_message "For a trusted certificate, use Let's Encrypt or a commercial certificate."
            log_message "If you're using Cloudflare, consider using Cloudflare Origin Certificates instead."
        fi
        
        return 0
    else
        log_message "ERROR: Final Nginx configuration test failed. Please check the error messages above."
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
    get_interactive_input "SSL type (letsencrypt, self-signed, or cloudflare)" ssl_type
    if [ "$ssl_type" != "letsencrypt" ] && [ "$ssl_type" != "self-signed" ] && [ "$ssl_type" != "cloudflare" ]; then
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
    
    if [ -z "$ssl_type" ] || ([ "$ssl_type" != "letsencrypt" ] && [ "$ssl_type" != "self-signed" ] && [ "$ssl_type" != "cloudflare" ]); then
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

# Function to check SSL certificate for a domain
check_ssl() {
    local domain="$1"
    
    log_message "Checking SSL certificate for $domain..."
    
    # Check if OpenSSL is installed
    if ! command_exists openssl; then
        log_message "ERROR: OpenSSL is not installed. Cannot check SSL certificate."
        return 1
    fi
    
    # Check if the domain resolves
    host_output=$(host "$domain" 2>&1)
    if echo "$host_output" | grep -q "not found" || echo "$host_output" | grep -q "NXDOMAIN"; then
        log_message "WARNING: Domain $domain does not resolve to an IP address."
        log_message "Make sure DNS is configured correctly before setting up SSL."
    fi
    
    # First, check if the site is accessible via HTTPS
    log_message "Checking if HTTPS is accessible for $domain..."
    if ! curl -s -o /dev/null -w "%{http_code}" "https://$domain" > /dev/null 2>&1; then
        log_message "WARNING: HTTPS is not accessible for $domain."
    fi
    
    # Check if the Nginx configuration exists
    if [ -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        log_message "Nginx configuration exists for $domain."
        
        # Check if SSL is configured
        if grep -q "ssl_certificate" "$NGINX_SITES_AVAILABLE/$domain.conf"; then
            log_message "SSL is configured in the Nginx configuration."
            
            # Extract SSL certificate paths
            local ssl_cert=$(grep "ssl_certificate " "$NGINX_SITES_AVAILABLE/$domain.conf" | grep -v "ssl_certificate_key" | sed 's/.*ssl_certificate //; s/;//')
            local ssl_key=$(grep "ssl_certificate_key" "$NGINX_SITES_AVAILABLE/$domain.conf" | sed 's/.*ssl_certificate_key //; s/;//')
            
            log_message "SSL Certificate path: $ssl_cert"
            log_message "SSL Key path: $ssl_key"
            
            # Check if certificate files exist
            if [ -f "$ssl_cert" ] && [ -f "$ssl_key" ]; then
                log_message "SSL certificate files exist."
                
                # Check certificate expiration
                local expiry=$(openssl x509 -enddate -noout -in "$ssl_cert" | sed 's/notAfter=//')
                local expiry_date=$(date -d "$expiry" +%s)
                local current_date=$(date +%s)
                local days_left=$(( (expiry_date - current_date) / 86400 ))
                
                log_message "Certificate expiry date: $expiry"
                log_message "Days until expiration: $days_left"
                
                if [ "$days_left" -lt 0 ]; then
                    log_message "ERROR: Certificate has EXPIRED!"
                elif [ "$days_left" -lt 30 ]; then
                    log_message "WARNING: Certificate will expire in less than 30 days!"
                fi
                
                # Check certificate issuer
                local issuer=$(openssl x509 -issuer -noout -in "$ssl_cert" | sed 's/issuer= //')
                log_message "Certificate issuer: $issuer"
                
                if echo "$issuer" | grep -q "Let's Encrypt"; then
                    log_message "This is a Let's Encrypt certificate."
                elif echo "$issuer" | grep -q "Cloudflare"; then
                    log_message "This is a Cloudflare Origin Certificate."
                elif echo "$issuer" | grep -qi "CN=$domain"; then
                    log_message "This is a self-signed certificate."
                    log_message "IMPORTANT: Self-signed certificates will show as 'Not Secure' in browsers."
                    log_message "This is expected behavior as browsers don't trust self-signed certificates."
                    log_message "For a trusted certificate, use Let's Encrypt or a commercial certificate provider."
                else
                    log_message "Certificate from another issuer."
                fi
                
                # Check if the certificate matches the domain
                local common_name=$(openssl x509 -noout -subject -in "$ssl_cert" | sed -n 's/.*CN=\([^\/]*\).*/\1/p')
                log_message "Certificate common name: $common_name"
                
                if [ "$common_name" != "$domain" ] && [ "$common_name" != "*.$domain" ] && [ "$common_name" != "*.$(echo "$domain" | cut -d. -f2-)" ]; then
                    log_message "WARNING: Certificate common name does not match the domain!"
                    log_message "This will cause browsers to show certificate warnings."
                fi
                
                # Check for Cloudflare proxy
                local cloudflare_check=$(dig +short "$domain" | grep -E '^(173\.245\.|103\.21\.|103\.22\.|103\.23\.|103\.24\.|104\.16\.|104\.17\.|104\.18\.|104\.19\.|104\.20\.|108\.162\.|141\.101\.|162\.158\.|172\.64\.|172\.65\.|172\.66\.|172\.67\.|198\.41\.|131\.0\.)')
                
                if [ -n "$cloudflare_check" ]; then
                    log_message "Domain appears to be using Cloudflare proxy."
                    log_message "Note: When using Cloudflare proxy (orange cloud), visitors see Cloudflare's certificate."
                    log_message "If you're using self-signed certificates, make sure to configure SSL/TLS encryption mode"
                    log_message "in Cloudflare to 'Full' or 'Full (strict)' in your Cloudflare dashboard."
                fi
                
                # Check if the certificate is valid for the domain
                if echo | openssl s_client -servername "$domain" -connect "$domain:443" -verify_hostname "$domain" > /dev/null 2>&1; then
                    log_message "Certificate validation successful for $domain."
                else
                    log_message "WARNING: Certificate validation failed for $domain."
                    log_message "This could be due to a mismatched certificate or other SSL configuration issues."
                fi
                
                return 0
            else
                log_message "ERROR: SSL certificate files do not exist at the paths specified in the configuration."
                [ ! -f "$ssl_cert" ] && log_message "Missing certificate file: $ssl_cert"
                [ ! -f "$ssl_key" ] && log_message "Missing key file: $ssl_key"
                return 1
            fi
        else
            log_message "WARNING: SSL is not configured in the Nginx configuration for $domain."
            return 1
        fi
    else
        log_message "ERROR: No Nginx configuration found for $domain."
        log_message "Run --add-domain to create a configuration for this domain first."
        return 1
    fi
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
    echo "                         SSL_TYPE can be:"
    echo "                           'letsencrypt' - Use Let's Encrypt (trusted certificates)"
    echo "                           'self-signed' - Use self-signed certificates (will show as not secure)"
    echo "                           'cloudflare'  - Use Cloudflare Origin Certificate (requires Cloudflare)"
    echo "  --from-config FILE     Setup domains from a configuration file"
    echo "  --help                 Display this help message"
    echo "  --check-ssl DOMAIN     Check SSL certificate for a domain"
    echo
    echo "Examples:"
    echo "  $0 --initial-setup"
    echo "  $0 --add-domain example.com 192.168.1.100 8080 admin@example.com letsencrypt"
    echo "  $0 --from-config domains.conf"
    echo "  $0 --check-ssl example.com"
    echo
    echo "Configuration file format:"
    echo "  admin_email=admin@example.com"
    echo "  ssl_type=self-signed"
    echo "  # Lines starting with # are comments"
    echo "  example.com,192.168.1.100,8080"
    echo "  example.org,192.168.1.100,8081"
    echo
    echo "Notes on SSL Types:"
    echo "  - letsencrypt: Provides trusted certificates, requires public DNS pointing to your server"
    echo "  - self-signed: Works for internal use but browsers will show 'Not Secure' warnings"
    echo "  - cloudflare: Use when your domain is managed by Cloudflare with proxy enabled"
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
    --check-ssl)
        if [ "$#" -ne 2 ]; then
            log_message "ERROR: Missing domain for --check-ssl"
            show_help
            exit 1
        fi
        check_ssl "$2"
        ;;
    --help)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac