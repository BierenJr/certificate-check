#!/bin/bash

################################################################################
# Script: check_certs.sh
# Purpose: Verify presence of root and intermediate certificates in all SAS 
#          trust stores by comparing certificate fingerprints (not aliases)
# Checks: 
#   - trustedcerts.pem files
#   - trustedcerts.jks files
#   - jssecacerts files
# Output: Reports PRESENT or NOT FOUND for each certificate in each store
################################################################################

# Configuration
ROOT_CERT="root.pem"
INT_CERT="intermediate.pem"

BASE_PATH="/mnt/sas/mid/"
JKS_PASS="changeit"

# Installation directories
INSTALL_DIRS=(
    "install/"
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

# Check all stores
for dir in "${INSTALL_DIRS[@]}"; do
    # PEM
    pem="$BASE_PATH/$dir/SASSecurityCertificateFramework/1.1/cacerts/trustedcerts.pem"
    echo "$pem"
    check_pem "$pem" "$ROOT_FP" && echo "  Root: PRESENT" || echo "  Root: NOT FOUND"
    check_pem "$pem" "$INT_FP" && echo "  Intermediate: PRESENT" || echo "  Intermediate: NOT FOUND"
    
    # JKS
    jks="$BASE_PATH/$dir/SASSecurityCertificateFramework/1.1/cacerts/trustedcerts.jks"
    echo "$jks"
    check_jks "$jks" "$ROOT_FP" && echo "  Root: PRESENT" || echo "  Root: NOT FOUND"
    check_jks "$jks" "$INT_FP" && echo "  Intermediate: PRESENT" || echo "  Intermediate: NOT FOUND"
    
    # jssecacerts
    jssec="$BASE_PATH/$dir/SASPrivateJavaRuntimeEnvironment/9.4/jre/lib/security/jssecacerts"
    echo "$jssec"
    check_jks "$jssec" "$ROOT_FP" && echo "  Root: PRESENT" || echo "  Root: NOT FOUND"
    check_jks "$jssec" "$INT_FP" && echo "  Intermediate: PRESENT" || echo "  Intermediate: NOT FOUND"

    # cacerts
    cacert="$BASE_PATH/$dir/SASPrivateJavaRuntimeEnvironment/9.4/jre/lib/security/cacerts"
    echo "$cacert"
    check_jks "$cacert" "$ROOT_FP" && echo "  Root: PRESENT" || echo "  Root: NOT FOUND"
    check_jks "$cacert" "$INT_FP" && echo "  Intermediate: PRESENT" || echo "  Intermediate: NOT FOUND"
    
    echo ""

done
