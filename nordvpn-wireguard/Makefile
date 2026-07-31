# SPDX-License-Identifier: MIT
# Copyright 2026 Andrey Aleksandrov <aladex@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=nordvpn-wireguard
PKG_VERSION:=1.4.3
PKG_RELEASE:=1
PKG_MAINTAINER:=Andrey Aleksandrov <aladex@gmail.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/nordvpn-wireguard
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=NordVPN WireGuard backend
  URL:=https://github.com/Aladex/nordvpn-luci
  PKGARCH:=all
  DEPENDS:= \
	+ca-bundle \
	+curl \
	+kmod-wireguard \
	+rpcd \
	+rpcd-mod-ucode \
	+ucode \
	+ucode-mod-fs \
	+ucode-mod-math \
	+ucode-mod-ubus \
	+ucode-mod-uci \
	+ucode-mod-uloop \
	+wireguard-tools
endef

define Package/nordvpn-wireguard/description
NordVPN WireGuard service for OpenWrt: credential exchange, server-list cache,
WireGuard interface/peer generation, connectivity verification, scheduled
server rotation and runtime status. Usable from the CLI and ubus without LuCI.
Unofficial; not affiliated with or endorsed by Nord Security.
endef

define Package/nordvpn-wireguard/conffiles
/etc/config/nordvpn
endef

# Script-only package: nothing to compile.
define Build/Configure
endef

define Build/Compile
endef

define Package/nordvpn-wireguard/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/nordvpn $(1)/etc/config/nordvpn

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/nordvpn $(1)/etc/init.d/nordvpn

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-nordvpn-migrate $(1)/etc/uci-defaults/90-nordvpn-migrate

	$(INSTALL_DIR) $(1)/usr/share/ucode/nordvpn
	$(INSTALL_DATA) ./files/usr/share/ucode/nordvpn/*.uc $(1)/usr/share/ucode/nordvpn/
	$(SED) "s|^const VERSION = .*|const VERSION = '$(PKG_VERSION)-r$(PKG_RELEASE)';|" \
		$(1)/usr/share/ucode/nordvpn/common.uc

	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_DATA) ./files/usr/share/rpcd/ucode/nordvpn.uc $(1)/usr/share/rpcd/ucode/nordvpn.uc

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/nordvpn-cache-update $(1)/usr/bin/nordvpn-cache-update
	$(INSTALL_BIN) ./files/usr/bin/nordvpn-rotate $(1)/usr/bin/nordvpn-rotate
	$(INSTALL_BIN) ./files/usr/bin/nordvpn-service $(1)/usr/bin/nordvpn-service
endef

$(eval $(call BuildPackage,nordvpn-wireguard))
