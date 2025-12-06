#!/bin/bash
#
# Install firewall-viz to /usr/local/bin
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/firewall-viz"
INSTALL_PATH="/usr/local/bin/firewall-viz"

# Build if needed
if [ ! -f "$BINARY" ]; then
    echo "Building firewall-viz..."
    cd "$SCRIPT_DIR"
    cargo build --release
fi

# Install
echo "Installing to $INSTALL_PATH..."
sudo install -m 755 "$BINARY" "$INSTALL_PATH"

# Set capabilities so it can read nftables without full root
echo "Setting CAP_NET_ADMIN capability..."
sudo setcap cap_net_admin=ep "$INSTALL_PATH"

echo "Done! Run 'firewall-viz' to start."
