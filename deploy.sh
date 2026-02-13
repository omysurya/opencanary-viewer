#!/bin/bash

# OpenCanary Viewer Deployment Script

set -e

echo "================================"
echo "OpenCanary Viewer Setup"
echo "================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    echo "Visit: https://go.dev/doc/install"
    exit 1
fi

echo "✅ Go version: $(go version)"
echo ""

# Build the application
echo "📦 Building application..."
go build -o opencanary-viewer opencanary-viewer.go

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""

# Make executable
chmod +x opencanary-viewer

# Check if log file exists
LOG_FILE="/var/tmp/opencanary.log"
if [ ! -f "$LOG_FILE" ]; then
    echo "⚠️  Warning: Log file $LOG_FILE not found!"
    echo "   Make sure OpenCanary is running and logging to this location."
    echo ""
fi

# Check if we need sudo
if [ ! -r "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    echo "⚠️  Warning: Cannot read $LOG_FILE"
    echo "   You may need to run the viewer with sudo"
    echo ""
fi

echo "================================"
echo "Setup Complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Edit opencanary-viewer.go and update the allowedIPs list"
echo "2. Run: sudo ./opencanary-viewer"
echo "3. Access: http://your-ip:8080"
echo ""
echo "To run as a service, see README.md for systemd configuration"
echo ""
