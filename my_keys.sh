#!/bin/bash

# Minimal key generation script (renamed to my_keys.sh)
# - creates `keys/` if needed
# - generates key files per design
# - writes dotenv file `keys/keys.env` with absolute paths

set -euo pipefail

mkdir -p keys

# Generate signing keys (Ed25519) for Admin, Registrar, Tallier
openssl genpkey -algorithm ed25519 -out keys/registrar_sign_priv.pem
openssl pkey -in keys/registrar_sign_priv.pem -pubout -out keys/registrar_sign_pub.pem

openssl genpkey -algorithm ed25519 -out keys/admin_sign_priv.pem
openssl pkey -in keys/admin_sign_priv.pem -pubout -out keys/admin_sign_pub.pem

openssl genpkey -algorithm ed25519 -out keys/tallier_sign_priv.pem
openssl pkey -in keys/tallier_sign_priv.pem -pubout -out keys/tallier_sign_pub.pem

# Election RSA keypair (used to encrypt ballots)
openssl genpkey -algorithm RSA -out keys/election_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/election_priv.pem -pubout -out keys/election_pub.pem

# Server RSA keypair (used to encrypt hashed IDs sent to server)
openssl genpkey -algorithm RSA -out keys/server_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/server_priv.pem -pubout -out keys/server_pub.pem

# Write dotenv file with only the keys required by the design
ENV_FILE="$PWD/keys/keys.env"
cat > "$ENV_FILE" <<EOF
# Registrar signing (Ed25519)
REGISTRAR_SIGN_PRIV_KEY=$PWD/keys/registrar_sign_priv.pem
REGISTRAR_SIGN_PUB_KEY=$PWD/keys/registrar_sign_pub.pem
# Registrar encryption (RSA) - used to store names so only Registrar can decrypt
REGISTRAR_ENC_PRIV_KEY=$PWD/keys/registrar_enc_priv.pem
REGISTRAR_ENC_PUB_KEY=$PWD/keys/registrar_enc_pub.pem
# Admin signing (Ed25519)
ADMIN_SIGN_PRIV_KEY=$PWD/keys/admin_sign_priv.pem
ADMIN_SIGN_PUB_KEY=$PWD/keys/admin_sign_pub.pem
# Tallier signing (Ed25519)
TALLIER_SIGN_PRIV_KEY=$PWD/keys/tallier_sign_priv.pem
TALLIER_SIGN_PUB_KEY=$PWD/keys/tallier_sign_pub.pem

# Election RSA (used to encrypt ballots). Election private key is to be split with SSS among trustees.
ELECTION_PRIV_KEY=$PWD/keys/election_priv.pem
ELECTION_PUB_KEY=$PWD/keys/election_pub.pem

# Server RSA (used to encrypt hashed identifiers sent to server)
SERVER_PRIV_KEY=$PWD/keys/server_priv.pem
SERVER_PUB_KEY=$PWD/keys/server_pub.pem
EOF

chmod 600 keys/*.pem || true

echo "Keys written to $PWD/keys and $ENV_FILE"

exit 0
