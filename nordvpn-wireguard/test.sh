#!/bin/sh
# SPDX-License-Identifier: 0BSD
# Version smoke test for the OpenWrt packages-feed CI harness.
# Invoked as: test.sh <package-name> <version>
# Succeeds when the installed init script reports the expected version.

/etc/init.d/nordvpn version 2>&1 | grep -q "$2"
