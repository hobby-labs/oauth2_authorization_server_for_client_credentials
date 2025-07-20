#!/bin/bash

# Key Rotation Script for OAuth2 Authorization Server

KEYS_FILE="src/main/resources/keys.yml"

echo "=== OAuth2 Key Rotation Tool ==="
echo

# Function to show current configuration
show_current_config() {
    echo "Current Configuration:"
    echo "Primary Key: $(grep 'primary-key:' $KEYS_FILE | sed 's/.*primary-key: *"\?\([^"]*\)"\?.*/\1/')"
    echo "Key Rotation: $(grep 'key-rotation:' $KEYS_FILE | sed 's/.*key-rotation: *\([^ ]*\).*/\1/')"
    echo
    
    echo "Available Keys:"
    grep -A 1 "^ *[a-zA-Z-]*:" $KEYS_FILE | grep -v "config:" | grep -v "primary-key:" | grep -v "key-rotation:" | grep ":" | sed 's/^ */- /' | sed 's/:.*$//'
    echo
}

# Function to rotate to backup key
rotate_to_backup() {
    echo "Rotating from primary key 'ec' to backup key 'ec-backup'..."
    
    # Update primary key
    sed -i 's/primary-key: *"ec"/primary-key: "ec-backup"/' $KEYS_FILE
    
    # Ensure key rotation is enabled
    sed -i 's/key-rotation: *false/key-rotation: true/' $KEYS_FILE
    
    echo "✅ Key rotation completed!"
    echo "New primary key: ec-backup"
    echo "Key rotation: enabled"
}

# Function to rotate back to original key
rotate_to_primary() {
    echo "Rotating from backup key 'ec-backup' to primary key 'ec'..."
    
    # Update primary key
    sed -i 's/primary-key: *"ec-backup"/primary-key: "ec"/' $KEYS_FILE
    
    echo "✅ Key rotation completed!"
    echo "New primary key: ec"
    echo "Key rotation: enabled (keeping both keys available)"
}

# Function to disable key rotation (primary key only)
disable_rotation() {
    echo "Disabling key rotation (primary key only mode)..."
    
    # Disable key rotation
    sed -i 's/key-rotation: *true/key-rotation: false/' $KEYS_FILE
    
    echo "✅ Key rotation disabled!"
    echo "Only primary key will be used for signing and verification"
}

# Function to enable key rotation
enable_rotation() {
    echo "Enabling key rotation (all keys available for verification)..."
    
    # Enable key rotation
    sed -i 's/key-rotation: *false/key-rotation: true/' $KEYS_FILE
    
    echo "✅ Key rotation enabled!"
    echo "All keys will be available for verification, primary key for signing"
}

# Main menu
while true; do
    show_current_config
    
    echo "Options:"
    echo "1) Rotate to backup key (ec → ec-backup)"
    echo "2) Rotate to primary key (ec-backup → ec)"
    echo "3) Enable key rotation"
    echo "4) Disable key rotation"
    echo "5) Show current config"
    echo "6) Exit"
    echo
    
    read -p "Select option (1-6): " choice
    echo
    
    case $choice in
        1)
            rotate_to_backup
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            ;;
        2)
            rotate_to_primary
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            ;;
        3)
            enable_rotation
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            ;;
        4)
            disable_rotation
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            ;;
        5)
            # Just show config again
            ;;
        6)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            echo
            ;;
    esac
done
