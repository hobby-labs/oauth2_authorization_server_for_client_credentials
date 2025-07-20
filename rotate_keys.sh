#!/bin/bash

# Key Rotation Script for OAuth2 Authorization Server

KEYS_FILE="src/main/resources/keys.yml"

echo "=== OAuth2 Key Rotation Tool ==="
echo

# Function to show current configuration
show_current_config() {
    echo "Current Configuration:"
    echo "Primary Key: $(grep 'primary-key:' $KEYS_FILE | sed 's/.*primary-key: *"\?\([^"]*\)"\?.*/\1/')"
    echo
    
    echo "Available Keys:"
    grep -A 1 "^ *[a-zA-Z-]*:" $KEYS_FILE | grep -v "config:" | grep -v "primary-key:" | grep ":" | sed 's/^ */- /' | sed 's/:.*$//'
    echo
}

# Function to rotate to backup key
rotate_to_backup() {
    echo "Rotating from primary key 'ec' to backup key 'ec-backup'..."
    
    # Update primary key
    sed -i 's/primary-key: *"ec"/primary-key: "ec-backup"/' $KEYS_FILE
    
    echo "✅ Key rotation completed!"
    echo "New primary key: ec-backup"
    echo "Key rotation: always enabled (all keys available for verification)"
}

# Function to rotate back to original key
rotate_to_primary() {
    echo "Rotating from backup key 'ec-backup' to primary key 'ec'..."
    
    # Update primary key
    sed -i 's/primary-key: *"ec-backup"/primary-key: "ec"/' $KEYS_FILE
    
    echo "✅ Key rotation completed!"
    echo "New primary key: ec"
    echo "Key rotation: always enabled (all keys available for verification)"
}

# Main menu
while true; do
    show_current_config
    
    echo "Options:"
    echo "1) Rotate to backup key (ec → ec-backup)"
    echo "2) Rotate to primary key (ec-backup → ec)"
    echo "3) Show current config"
    echo "4) Exit"
    echo
    
    read -p "Select option (1-4): " choice
    echo
    
    case $choice in
        1)
            rotate_to_backup
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            exit 0
            ;;
        2)
            rotate_to_primary
            echo
            echo "⚠️  Remember to restart the application to apply changes!"
            echo
            exit 0
            ;;
        3)
            # Just show config again
            ;;
        4)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            echo
            exit 0
            ;;
    esac
done
