#!/bin/bash

# Create keys directory if it doesn't exist
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

# Export environment variables
export REGISTRAR_PRIV_KEY="$PWD/keys/registrar_sign_priv.pem"
export REGISTRAR_PUB_KEY="$PWD/keys/registrar_sign_pub.pem"
export ADMIN_PRIV_KEY="$PWD/keys/admin_sign_priv.pem"
export ADMIN_PUB_KEY="$PWD/keys/admin_sign_pub.pem"
export TALLIER_PRIV_KEY="$PWD/keys/tallier_enc_priv.pem"
export TALLIER_PUB_KEY="$PWD/keys/tallier_enc_pub.pem"

echo "All keys generated in the 'keys' folder and environment variables exported."
