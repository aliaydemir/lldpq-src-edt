#!/usr/bin/env bash
# LLDPq Update Script — thin wrapper around install.sh
#
# Copyright (c) 2024-2026 LLDPq Project
# Licensed under MIT License - see LICENSE file for details
#
# install.sh now handles both fresh install and update automatically.
# This wrapper exists for backward compatibility.
#
# Usage: ./update.sh [-y] [--enable-telemetry] [--disable-telemetry]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh" "$@"
