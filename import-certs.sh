#!/bin/bash

################################################################################
# Script: import_certs.sh
# Purpose: Import root and intermediate certificates to SAS trust stores only
#          if they are missing (verified by fingerprint, not alias)
# Actions:
#   - Checks each trust store for certificate presence
#   - Imports certificates only where missing
#   - Handles PEM files (cat append) and JKS files (keytool import)
################################################################################

# Configuration
ROOT_CERT="root.pem"
ROOT_ALIAS="root-alias"

INT_CERT="intermediate.pem"
INT_ALIAS="intermediate-alias"

BASE_PATH="/sashome"
JKS_PASS="changeit"

# Installation directories
INSTALL_DIRS=(
    "install/va"
    "install/midtier"
    "install/meta"
    "install/compute"
)

# Get fingerprints
ROOT_FP=$(openssl x509 -in "$ROOT_CERT" -noout -fingerprint -sha256)
INT_FP=$(openssl x509 -in "$INT_CERT" -noout -fingerprint -sha256)

# Function to check JKS/JSSECACERTS
check_jks() {
    local keystore=$1
    local fingerprint=$2
    
    [ ! -f "$keystore" ] && return 1
    
    keytool -list -rfc -keystore "$keystore" -storepass "$JKS_PASS" 2>/dev/null | \
    grep -A 50 "BEGIN CERTIFICATE" | \
    openssl x509 -noout -fingerprint -sha256 2>/dev/null | \
    grep -qF "$fingerprint"
}

# Function to check PEM
check_pem() {
    local pemfile=$1
    local fingerprint=$2
    
    [ ! -f "$pemfile" ] && return 1
    
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$pemfile" | \
    openssl x509 -noout -fingerprint -sha256 2>/dev/null | \
    grep -qF "$fingerprint"
}

# Import to PEM
import_pem() {
    local pemfile=$1
    local cert=$2
    
    echo "Importing to $pemfile"
    cat "$cert" >> "$pemfile"
}

# Import to JKS
import_jks() {
    local keystore=$1
    local cert=$2
    local alias=$3
    
    echo "Importing to $keystore"
    keytool -importcert -noprompt -file "$cert" -keystore "$keystore" -alias "$alias" -storepass "$JKS_PASS"
}

# Check and import
for dir in "${INSTALL_DIRS[@]}"; do
    echo "Processing $dir..."
    
    # PEM
    pem="$BASE_PATH/$dir/SASSecurityCertificateFramework/1.1/cacerts/trustedcerts.pem"
    if [ -f "$pem" ]; then
        check_pem "$pem" "$ROOT_FP" || import_pem "$pem" "$ROOT_CERT"
        check_pem "$pem" "$INT_FP" || import_pem "$pem" "$INT_CERT"
    fi
    
    # JKS
    jks="$BASE_PATH/$dir/SASSecurityCertificateFramework/1.1/cacerts/trustedcerts.jks"
    if [ -f "$jks" ]; then
        check_jks "$jks" "$ROOT_FP" || import_jks "$jks" "$ROOT_CERT" "$ROOT_ALIAS"
        check_jks "$jks" "$INT_FP" || import_jks "$jks" "$INT_CERT" "$INT_ALIAS"
    fi
    
    # jssecacerts
    jssec="$BASE_PATH/$dir/SASPrivateJavaRuntimeEnvironment/9.4/jre/lib/security/jssecacerts"
    if [ -f "$jssec" ]; then
        check_jks "$jssec" "$ROOT_FP" || import_jks "$jssec" "$ROOT_CERT" "$ROOT_ALIAS"
        check_jks "$jssec" "$INT_FP" || import_jks "$jssec" "$INT_CERT" "$INT_ALIAS"
    fi
    
    # cacerts
    cacert="$BASE_PATH/$dir/SASPrivateJavaRuntimeEnvironment/9.4/jre/lib/security/cacerts"
    if [ -f "$cacert" ]; then
        check_jks "$cacert" "$ROOT_FP" || import_jks "$cacert" "$ROOT_CERT" "$ROOT_ALIAS"
        check_jks "$cacert" "$INT_FP" || import_jks "$cacert" "$INT_CERT" "$INT_ALIAS"
    fi
    
    echo ""
done


echo "Import complete"