include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nordvpn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=0BSD

LUCI_TITLE:=LuCI support for NordVPN WireGuard
LUCI_DESCRIPTION:=Web interface for configuring NordVPN WireGuard with automatic server rotation and custom routing tables
LUCI_DEPENDS:=+luci-base +luci-proto-wireguard +luci-lib-jsonc +curl +openssl-util
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/nordvpn-cache enable
	/etc/init.d/nordvpn-cache start
	/etc/init.d/nordvpn-rotate enable
	/etc/init.d/nordvpn-rotate start
	rm -rf /tmp/luci-*
}
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
