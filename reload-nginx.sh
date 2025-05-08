#!/bin/bash

# Test Nginx configuration
echo "Testing Nginx configuration..."
nginx -t

# If the test was successful, reload Nginx
if [ $? -eq 0 ]; then
  echo "Reloading Nginx..."
  nginx -s reload
  echo "Nginx reloaded successfully."
else
  echo "Nginx configuration test failed. Not reloading."
  exit 1
fi