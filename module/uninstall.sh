#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/tricky_store

# Kill daemon process
for pid in $(pidof TEESimulator); do
    kill -9 "$pid" 2>/dev/null
done

# Clean up persistent state
rm -rf "$CONFIG_DIR/persistent_keys"
rm -f "$CONFIG_DIR/tee_status.txt"
rm -f "$CONFIG_DIR/boot_hash.bin" "$CONFIG_DIR/boot_key.bin"
rm -f "$CONFIG_DIR/security_patch.txt"
