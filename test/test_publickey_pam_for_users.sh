#! /bin/bash

export IRODS_PROXY_USER=""
export IRODS_PROXY_PASSWORD=""
export IRODS_HOST="data.cyverse.org"
export IRODS_PORT=1247
export IRODS_ZONE="iplant"
export IRODS_AUTH_SCHEME="pam_for_users"
export IRODS_REQUIRE_CS_NEGOTIATION=true
export IRODS_CS_NEGOTIATION_POLICY=CS_NEG_DONT_CARE
export IRODS_SSL_CA_CERT_PATH="/etc/ssl/certs/ca-certificates.crt"
export IRODS_SSL_ALGORITHM="AES-256-CBC"
export IRODS_SSL_KEY_SIZE=32
export IRODS_SSL_SALT_SIZE=8
export IRODS_SSL_HASH_ROUNDS=16
export SFTPGO_AUTHD_USERNAME="iychoi"
export SFTPGO_AUTHD_PASSWORD=""
export SFTPGO_AUTHD_PUBLIC_KEY="ssh-rsa XXXXX"
export SFTPGO_AUTHD_IP="10.10.10.10"

../bin/sftpgo-auth-irods --fake