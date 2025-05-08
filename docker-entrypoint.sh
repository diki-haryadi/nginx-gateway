#!/bin/sh
set -e

# Create required directories if they don't exist
mkdir -p /app/nginx/conf.d
mkdir -p /app/nginx/templates
mkdir -p /data

# If the database doesn't exist, initialize it
if [ ! -f /data/services.db ]; then
  echo "Initializing new database..."
  touch /data/services.db
fi

# Copy Nginx templates if they don't exist
if [ ! -f /app/nginx/templates/domain.conf.template ]; then
  echo "Setting up Nginx templates..."
  cp /app/nginx/templates/*.template /app/nginx/templates/
fi

# Make the database writable
chmod 666 /data/services.db

# Start the application
exec /app/service-manager