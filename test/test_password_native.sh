#! /bin/bash

export IRODS_PROXY_USER=""
export IRODS_PROXY_PASSWORD=""
export IRODS_HOST="data.cyverse.org"
export IRODS_PORT=1247
export IRODS_ZONE="iplant"
export IRODS_REQUIRE_CS_NEGOTIATION=true
export IRODS_CS_NEGOTIATION_POLICY=CS_NEG_DONT_CARE
export SFTPGO_AUTHD_USERNAME="iychoi"
export SFTPGO_AUTHD_PASSWORD=""
export SFTPGO_AUTHD_PUBLIC_KEY=""
export SFTPGO_AUTHD_IP="10.10.10.10"

../bin/sftpgo-auth-irods --fake