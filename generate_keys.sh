#!/bin/bash

# Minimal key generation script
# - creates `keys/` if needed
# - generates key files
# - writes dotenv file `keys/keys.env` with absolute paths

set -euo pipefail

mkdir -p keys

# Registrar RSA (encryption share)
openssl genpkey -algorithm RSA -out keys/registrar_enc_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/registrar_enc_priv.pem -pubout -out keys/registrar_enc_pub.pem

# Tallier RSA (encryption share)
openssl genpkey -algorithm RSA -out keys/tallier_enc_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/tallier_enc_priv.pem -pubout -out keys/tallier_enc_pub.pem

# Registrar signing key (Ed25519)
openssl genpkey -algorithm ed25519 -out keys/registrar_sign_priv.pem
openssl pkey -in keys/registrar_sign_priv.pem -pubout -out keys/registrar_sign_pub.pem

# Admin signing key (Ed25519)
openssl genpkey -algorithm ed25519 -out keys/admin_sign_priv.pem
openssl pkey -in keys/admin_sign_priv.pem -pubout -out keys/admin_sign_pub.pem

# Admin RSA keypair for encryption
openssl genpkey -algorithm RSA -out keys/admin_enc_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/admin_enc_priv.pem -pubout -out keys/admin_enc_pub.pem

# Tallier signing key (Ed25519)
openssl genpkey -algorithm ed25519 -out keys/tallier_sign_priv.pem
openssl pkey -in keys/tallier_sign_priv.pem -pubout -out keys/tallier_sign_pub.pem

# Write dotenv file with paths (no extra output)
ENV_FILE="$PWD/keys/keys.env"
cat > "$ENV_FILE" <<EOF
# Registrar signing (Ed25519)
REGISTRAR_SIGN_PRIV_KEY=$PWD/keys/registrar_sign_priv.pem
REGISTRAR_SIGN_PUB_KEY=$PWD/keys/registrar_sign_pub.pem
# Registrar encryption (RSA)
REGISTRAR_ENC_PRIV_KEY=$PWD/keys/registrar_enc_priv.pem
REGISTRAR_ENC_PUB_KEY=$PWD/keys/registrar_enc_pub.pem

# Admin signing (Ed25519)
ADMIN_SIGN_PRIV_KEY=$PWD/keys/admin_sign_priv.pem
ADMIN_SIGN_PUB_KEY=$PWD/keys/admin_sign_pub.pem
# Admin encryption (RSA)
ADMIN_ENC_PRIV_KEY=$PWD/keys/admin_enc_priv.pem
ADMIN_ENC_PUB_KEY=$PWD/keys/admin_enc_pub.pem

# Tallier signing (Ed25519)
TALLIER_SIGN_PRIV_KEY=$PWD/keys/tallier_sign_priv.pem
TALLIER_SIGN_PUB_KEY=$PWD/keys/tallier_sign_pub.pem
# Tallier encryption (RSA)
TALLIER_ENC_PRIV_KEY=$PWD/keys/tallier_enc_priv.pem
TALLIER_ENC_PUB_KEY=$PWD/keys/tallier_enc_pub.pem

# Backwards-compatible names (old scripts may read these)
REGISTRAR_PRIV_KEY=$PWD/keys/registrar_sign_priv.pem
REGISTRAR_PUB_KEY=$PWD/keys/registrar_sign_pub.pem
ADMIN_PRIV_KEY=$PWD/keys/admin_sign_priv.pem
ADMIN_PUB_KEY=$PWD/keys/admin_sign_pub.pem
TALLIER_PRIV_KEY=$PWD/keys/tallier_enc_priv.pem
TALLIER_PUB_KEY=$PWD/keys/tallier_enc_pub.pem
EOF

exit 0
