#!/bin/sh

# NordVPN LuCI Module Installation Script (manual install without building the ipk)

ROUTER_IP="${1:-192.168.1.1}"
ROUTER_USER="${2:-root}"

echo "Installing NordVPN LuCI module to $ROUTER_USER@$ROUTER_IP"

# Create directories
echo "Creating directories..."
ssh "$ROUTER_USER@$ROUTER_IP" "mkdir -p /usr/lib/lua/luci/controller /usr/lib/lua/luci/view/nordvpn /usr/lib/lua/luci/nordvpn"

# Copy Lua modules
echo ""
echo "Copying NordVPN controller..."
cat luasrc/controller/nordvpn.lua | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/lib/lua/luci/controller/nordvpn.lua"

echo "Copying cache module..."
cat luasrc/nordvpn/cache.lua | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/lib/lua/luci/nordvpn/cache.lua"

echo "Copying NordVPN view template..."
cat luasrc/view/nordvpn/overview.htm | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/lib/lua/luci/view/nordvpn/overview.htm"

# Copy scripts
echo "Copying rotation worker..."
cat root/usr/bin/nordvpn-rotate | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/bin/nordvpn-rotate && chmod +x /usr/bin/nordvpn-rotate"

echo "Copying cache update script..."
cat root/usr/bin/nordvpn-cache-update | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /usr/bin/nordvpn-cache-update && chmod +x /usr/bin/nordvpn-cache-update"

# Copy services and default config
echo "Copying procd services..."
cat root/etc/init.d/nordvpn-rotate | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /etc/init.d/nordvpn-rotate && chmod +x /etc/init.d/nordvpn-rotate"
cat root/etc/init.d/nordvpn-cache | ssh "$ROUTER_USER@$ROUTER_IP" "cat > /etc/init.d/nordvpn-cache && chmod +x /etc/init.d/nordvpn-cache"

echo "Installing default config (if none exists)..."
ssh "$ROUTER_USER@$ROUTER_IP" "[ -f /etc/config/nordvpn ] || cat > /etc/config/nordvpn" < root/etc/config/nordvpn

# Enable and start services, clear LuCI cache
echo ""
echo "Enabling services..."
ssh "$ROUTER_USER@$ROUTER_IP" "/etc/init.d/nordvpn-cache enable && /etc/init.d/nordvpn-cache start && /etc/init.d/nordvpn-rotate enable && /etc/init.d/nordvpn-rotate start && rm -rf /tmp/luci-*"

echo ""
echo "Installation complete!"
echo ""
echo "Access the interface at:"
echo "  https://$ROUTER_IP/cgi-bin/luci/admin/vpn/nordvpn"
