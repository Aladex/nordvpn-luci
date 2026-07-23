#!/bin/sh

# NordVPN LuCI Module Installation Script

ROUTER_IP="${1:-192.168.1.1}"
ROUTER_USER="${2:-root}"

echo "Installing NordVPN LuCI module to $ROUTER_USER@$ROUTER_IP"

# Create directories
echo "Creating directories..."
ssh "$ROUTER_USER@$ROUTER_IP" "mkdir -p /usr/lib/lua/luci/controller /usr/lib/lua/luci/view/nordvpn"

# Copy controller
echo ""
echo "Copying NordVPN controller..."
cat luasrc/controller/nordvpn.lua | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/lib/lua/luci/controller/nordvpn.lua"

# Copy view template
echo "Copying NordVPN view template..."
cat luasrc/view/nordvpn/overview.htm | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/lib/lua/luci/view/nordvpn/overview.htm"

# Copy rotation script
echo "Copying NordVPN rotation script..."
cat nordvpn-rotate | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/bin/nordvpn-rotate && chmod +x /usr/bin/nordvpn-rotate"

# Copy cache update script (optional, if present in the repo)
if [ -f nordvpn-cache-update ]; then
	echo "Copying NordVPN cache update script..."
	cat nordvpn-cache-update | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/bin/nordvpn-cache-update && chmod +x /usr/bin/nordvpn-cache-update"
fi

# Clear LuCI cache
echo ""
echo "Clearing LuCI cache..."
ssh "$ROUTER_USER@$ROUTER_IP" "rm -rf /tmp/luci-*"

echo ""
echo "Installation complete!"
echo ""
echo "Access the interface at:"
echo "  https://$ROUTER_IP/cgi-bin/luci/admin/vpn/nordvpn"
