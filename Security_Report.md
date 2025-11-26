% Simple Electronic Voting System: Security and Design Report

# Introduction

Designing a secure electronic voting system is a bit like planning a group trip: everyone wants their voice heard, but you also want to make sure no one cheats, peeks at the ballots, or hijacks the itinerary. In this report, I’ll walk you through the design rationale, threat modeling, attackability, and secure design principles that shaped this system. I’ll use real-world analogies and examples to make the journey relatable, and I’ll point out the trade-offs and lessons learned along the way.

---

# 1. Design Rationale and Trade-offs

## Key Decisions and Their Security Rationale

### a. Environment-based Key Management
- **Decision:** All cryptographic keys and secrets are loaded from environment variables (via a dotenv file).
- **Why?** Hardcoding secrets is like leaving your house key under the doormat. By using environment variables, we keep secrets out of the codebase and make it easier to rotate or revoke them.
- **Trade-off:** Slightly more setup complexity, but much better security hygiene.

### b. Separate Signing and Encryption Keys
- **Decision:** Each role (Admin, Registrar, Tallier) has both a signing (Ed25519) and an encryption (RSA) key.
- **Why?** Using the right tool for the job: Ed25519 for signatures (fast, modern, secure), RSA for encryption (widely supported, threshold-friendly). This separation prevents accidental misuse (e.g., trying to encrypt with a signing key).
- **Trade-off:** More keys to manage, but clearer security boundaries and fewer cryptographic footguns.

### c. Threshold Decryption (Shamir Secret Sharing)
- **Decision:** The AES ballot encryption key is split using 2-of-3 Shamir secret sharing among Admin, Registrar, and Tallier.
- **Why?** No single party can decrypt ballots alone—at least two must cooperate. This is like requiring two keys to open a safe.
- **Trade-off:** Slightly more complexity in key management and recovery, but much stronger protection against insider threats.

### d. Peppering and Regex for ID Security
- **Decision:** Student IDs are validated with a regex and stored as peppered hashes.
- **Why?** Prevents attackers from guessing or precomputing valid IDs. The pepper is a secret ingredient—without it, hashes are useless to attackers.
- **Trade-off:** Users must follow a stricter ID format, but the system is much less vulnerable to enumeration attacks.

### e. Privacy-Preserving Tally
- **Decision:** Only the winning option(s) are revealed; no raw vote counts or voter mappings are exposed.
- **Why?** This is like announcing the winner of a contest without showing the full scoreboard—protects voter privacy and reduces the risk of coercion.
- **Trade-off:** Less transparency for auditors, but much stronger privacy for voters.

### f. Zero-Knowledge Proofs (ZKP) Design (Planned)
- **Decision:** Use ElGamal encryption and Schnorr OR-proofs to let voters prove their ballot is valid without revealing their choice.
- **Why?** This is the gold standard for privacy: you can prove you voted for a valid option, but no one (not even the server) can tell which one.
- **Trade-off:** More computational overhead and code complexity, but dramatically improved ballot secrecy and verifiability.

---

# 2. STRIDE Threat Modelling

STRIDE is a handy mnemonic for thinking about threats: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. Let’s walk through each, with concrete examples from this system.

## Spoofing
- **Scenario:** An attacker pretends to be a student or admin.
- **Affected:** Server, client, admin endpoints.
- **Mitigation:** ID regex validation, signature checks, admin secret. Only valid IDs and signed requests are accepted.
- **Why it works:** Attackers can’t easily guess valid IDs or forge signatures without the private key.

## Tampering
- **Scenario:** Someone tries to modify ballots or registration data in transit.
- **Affected:** Server, ballots, registration endpoints.
- **Mitigation:** All sensitive data is signed and/or encrypted. Ballots are encrypted client-side; signatures are verified server-side.
- **Why it works:** Tampered data fails signature or decryption checks and is rejected.

## Repudiation
- **Scenario:** A voter or admin denies taking an action (e.g., casting a vote, closing the election).
- **Affected:** Server logs, audit trail.
- **Mitigation:** All actions are signed with Ed25519 keys; signatures are stored with actions.
- **Why it works:** Signatures provide non-repudiation—only the key holder could have signed.

## Information Disclosure
- **Scenario:** An attacker tries to learn who voted for what, or the contents of ballots.
- **Affected:** Ballots, voter registry.
- **Mitigation:** Ballots are encrypted with AES-GCM; names are encrypted for the Registrar; hashes are peppered.
- **Why it works:** Without the decryption keys and pepper, attackers can’t recover sensitive data.

## Denial of Service (DoS)
- **Scenario:** Flooding the server with requests to disrupt voting.
- **Affected:** Server, all endpoints.
- **Mitigation:** (Current) No rate-limiting, but stateless design and minimal in-memory state reduce impact. (Future) Add rate-limiting and input validation.
- **Why it works:** Statelessness means a crash or restart loses little; rate-limiting would further reduce risk.

## Elevation of Privilege
- **Scenario:** A user tries to perform admin actions without proper rights.
- **Affected:** Admin endpoints, server state.
- **Mitigation:** Admin actions require both a signature and (optionally) an admin secret.
- **Why it works:** Attackers need both the private key and the secret—two factors are better than one.

---

# 3. Attackability Assessment

Let’s be honest: no system is invulnerable. Here’s how this one stacks up, with practical mitigations and existing controls.

## a. Key Leakage
- **Attack:** Private keys or secrets are stolen from disk.
- **Mitigation:** Use file permissions, secrets managers, and never commit keys to version control. The system already loads keys from env vars, making it easier to rotate or revoke them.

## b. ID Enumeration
- **Attack:** Attacker tries all possible IDs to find valid ones.
- **Mitigation:** Regex validation and peppered hashes make this much harder. For even more security, add rate-limiting and lockouts.

## c. Ballot Privacy Breach
- **Attack:** Server compromise exposes encrypted ballots.
- **Mitigation:** Ballots are encrypted client-side; threshold decryption means no single party can decrypt them. Even if the server is breached, ballots remain confidential.

## d. Insider Threats
- **Attack:** Admin, Registrar, or Tallier abuses their power.
- **Mitigation:** Threshold decryption requires at least two parties to cooperate. For even more assurance, keys can be stored offline or in HSMs.

## e. Replay/Impersonation
- **Attack:** Attacker replays old requests or impersonates a user.
- **Mitigation:** Signatures and ID validation help, but session tokens or one-time codes would further reduce risk.

---

# 4. Secure Design Methodology Evaluation

Let’s see how the system measures up against two classic principles.

## Principle of Least Privilege
- **How it’s followed:** Each component (Admin, Registrar, Tallier, Client) only has the keys and permissions it needs. For example, the Registrar can’t tally votes, and the Tallier can’t register voters.
- **Limitations:** The server still has broad access to in-memory state. In a real deployment, further isolation (e.g., microservices, containers) would help.

## Separation of Privilege
- **How it’s followed:** Threshold decryption means no single party can decrypt ballots. Admin actions require both a key and a secret.
- **Limitations:** If two parties collude, they can decrypt ballots. Using more shares or external hardware (HSMs) would further reduce risk.

---

# Conclusion

Building a secure voting system is a balancing act. Every design choice—whether it’s using environment variables for keys, splitting decryption power, or validating IDs—reflects a trade-off between usability, complexity, and security. By layering defenses and following established principles, this system aims to make cheating hard, privacy strong, and mistakes easy to catch. There’s always room for improvement, but with these foundations, you’re well on your way to a trustworthy election.

---

