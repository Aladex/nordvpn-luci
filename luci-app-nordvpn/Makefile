# SPDX-License-Identifier: MIT
# Copyright 2026 Andrey Aleksandrov <aladex@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nordvpn
PKG_VERSION:=1.4.3
PKG_RELEASE:=1
PKG_MAINTAINER:=Andrey Aleksandrov <aladex@gmail.com>
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI support for NordVPN WireGuard
LUCI_DESCRIPTION:=Web interface for the NordVPN WireGuard backend (nordvpn-wireguard): \
	runtime status, one-time credential setup, server selection, automatic \
	rotation and cache management. Unofficial; not affiliated with Nord Security.
LUCI_DEPENDS:=+luci-base +nordvpn-wireguard
LUCI_PKGARCH:=all

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
