#!/bin/bash
#
# CUMULUS-AUTOPROVISIONING
# LLDPq upgrade ZTP helper
#
# Used only for in-place OS upgrades where onie-install is called with:
#   -t /etc/nvue.d/startup.yaml
#
# Do not resolve serial mappings or fetch generated configs here. The running
# switch passes its saved startup.yaml directly to onie-install.

echo "LLDPq upgrade ZTP helper running"
ztp -d 2>/dev/null || true
exit 0
