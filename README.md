## System Architecture Overview

This project is a secure electronic voting system with the following main components:

- **main.py**: Entry point for users. Checks server connectivity, loads cryptographic keys, and presents a menu for user roles (Student, Admin, Registrar). Routes users to the appropriate interface.
- **myclient.py**: Handles student (voter) interactions: registration, authentication, and casting votes. Implements Schnorr ZKP for voter proof and encrypts ballots.
- **myadmin.py**: Provides admin functions: opening/closing elections, checking status. Admin actions are signed with Ed25519 keys.
- **myregistrar.py**: Manages voter registration. Hashes voter IDs, encrypts names, and issues Schnorr secrets for voters. Registrar actions are signed.
- **myserver.py**: Backend HTTP server. Manages election state, registered voters, ballots, and enforces all protocol rules. Verifies signatures, handles encrypted data, and coordinates cryptographic protocols.
- **mytallier.py**: Tallies votes after election closes. Reconstructs the election private key using Shamir’s Secret Sharing (SSS) and decrypts ballots.
- **my_utils.py**: Shared cryptographic utilities: key management, hashing, encryption/decryption, signing, ballot encryption, and environment variable loading.
- **my_sss.py**: Implements Shamir’s Secret Sharing for splitting and reconstructing private keys.
- **Schnorr_ZKP.py**: Implements Schnorr Zero-Knowledge Proof protocol for voter authentication.
- **my_db.JSON**: Stores student database (hashed IDs).
- **keys/**: Contains cryptographic key material and environment configuration.

## Security Mechanisms

### Advanced Cryptographic Functions

#### 1. Shamir’s Secret Sharing (SSS)
- **Location**: `my_sss.py`, used in `myserver.py` and `mytallier.py`.
- **Purpose**: Splits the election private key into multiple shares (e.g., for admin and tallier). Only a threshold of shares is needed to reconstruct the key, preventing any single party from decrypting ballots alone.
- **Implementation**: Election private key is split when ballots are requested. Shares are distributed via environment variables. The tallier and admin must cooperate to reconstruct the key for tallying.

#### 2. Schnorr Zero-Knowledge Proof (ZKP)
- **Location**: `Schnorr_ZKP.py`, used in `myclient.py`, `myregistrar.py`, and `myserver.py`.
- **Purpose**: Allows voters to prove knowledge of a secret (short secret) without revealing it, ensuring privacy and preventing vote fraud.
- **Implementation**: During registration, a Schnorr secret is generated and issued to the voter. When voting, the client generates a proof using this secret, which the server verifies before accepting the ballot.

### Standard Cryptographic Techniques

- **RSA Encryption**: Used for encrypting voter IDs, names, and ballots. Ballots are hybrid-encrypted (AES-GCM + RSA) for confidentiality.
- **Ed25519 Digital Signatures**: Used for signing admin and registrar actions. The server verifies signatures to ensure authenticity.
- **Hashing (SHA-256)**: Voter IDs are hashed before storage or transmission, protecting user privacy.
- **AES-GCM**: Used for symmetric encryption of ballot contents.
- **Key Management**: Keys are loaded from the `keys/` directory and environment variables, never hardcoded.

### Non-Cryptographic Security Techniques

- **Role-Based Access Control**: Only admins can open/close elections; only registrars can register voters; only registered voters can vote.
- **Input Validation**: User input is validated (e.g., voter ID format, menu choices).
- **Server Availability Check**: The client checks server status before allowing actions.
- **Separation of Duties**: Admin, registrar, and tallier have distinct roles, reducing risk of insider attacks.
- **Thread Safety**: Server uses locks to protect shared data structures.

## Security Flow Summary

1. **Registration**: Registrar hashes voter ID, encrypts name, and issues a Schnorr secret. Registration is signed and verified.
2. **Voting**: Voter submits an encrypted ballot and a Schnorr proof. The server verifies registration, proof, and prevents double voting.
3. **Tallying**: After election closes, admin and tallier reconstruct the election private key using SSS. Ballots are decrypted and tallied.

## File/Component Purpose Table

| File/Component      | Purpose/Role                                                                 |
|---------------------|------------------------------------------------------------------------------|
| main.py             | User entry/menu, role routing, server check                                  |
| myclient.py         | Voter registration, voting, Schnorr proof, ballot encryption                 |
| myadmin.py          | Admin actions (open/close election), Ed25519 signing                        |
| myregistrar.py      | Voter registration, Schnorr secret issuance, signing                        |
| myserver.py         | Backend server, state management, signature/ballot/proof verification       |
| mytallier.py        | Tallying votes, SSS key reconstruction, ballot decryption                   |
| my_utils.py         | Cryptographic utilities, key management, hashing, encryption                |
| my_sss.py           | Shamir’s Secret Sharing implementation                                      |
| Schnorr_ZKP.py      | Schnorr ZKP implementation                                                  |
| my_db.JSON          | Student database (hashed IDs)                                               |
| keys/               | Key material and environment configuration                                  |

## Component Interaction

- Users interact via `main.py`, which routes to the appropriate client.
- Clients communicate with the server (`myserver.py`) for all operations.
- Registrar manages registration and Schnorr secrets.
- Admin controls election state.
- Tallier and admin cooperate to tally votes securely.
- All sensitive data is encrypted, signed, and/or protected by advanced cryptographic protocols.

---

This report is based strictly on the actual code and structure of your project, with no assumptions beyond what is implemented.
