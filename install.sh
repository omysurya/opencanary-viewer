#!/bin/bash

# OpenCanary Viewer Systemd Installer

set -e

INSTALL_DIR="/opt/opencanary-viewer"
SERVICE_FILE="opencanary-viewer.service"
BINARY="opencanary-viewer"

echo "================================"
echo "OpenCanary Viewer - Systemd Install"
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Check if binary exists
if [ ! -f "./$BINARY" ]; then
    echo "❌ Binary not found. Please run ./deploy.sh first"
    exit 1
fi

# Create installation directory
echo "📁 Creating installation directory..."
mkdir -p $INSTALL_DIR

# Copy binary
echo "📋 Copying binary to $INSTALL_DIR..."
cp $BINARY $INSTALL_DIR/
chmod +x $INSTALL_DIR/$BINARY

# Update service file with correct path
echo "⚙️  Configuring systemd service..."
sed "s|/opt/opencanary-viewer|$INSTALL_DIR|g" $SERVICE_FILE > /tmp/$SERVICE_FILE
cp /tmp/$SERVICE_FILE /etc/systemd/system/

# Reload systemd
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable service
echo "✅ Enabling service..."
systemctl enable $SERVICE_FILE

echo ""
echo "================================"
echo "Installation Complete!"
echo "================================"
echo ""
echo "Commands:"
echo "  Start:   sudo systemctl start opencanary-viewer"
echo "  Stop:    sudo systemctl stop opencanary-viewer"
echo "  Status:  sudo systemctl status opencanary-viewer"
echo "  Logs:    sudo journalctl -u opencanary-viewer -f"
echo ""
echo "⚠️  Don't forget to edit $INSTALL_DIR/$BINARY"
echo "   and update the allowedIPs list before starting!"
echo ""
