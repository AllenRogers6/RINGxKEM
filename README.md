# RINGxKEM

WARNING!!
This is completely experimental code and is NOT meant to be used in production-ready software.

# The Protocol

This is a partially complete implementation of the [RINGxKEM](https://www.usenix.org/system/files/usenixsecurity25-hashimoto-key-exchange.pdf) scheme. As the name suggests, RINGxKEM combines two cryptographic primitives: Post-Quantum Ring Signatures and Post-Quantum Key Encapsulation Mechanisms (KEMs).

In a nutshell, a ring signature allows a member of a group to anonymously sign a message, proving they are one of a set of users, without revealing exactly which one signed the message to an outside observer. In RINGxKEM, the sender uses their private key to sign the handshake data over a ring that includes the recipient's public key and several random decoys. This model provides deniable authentication, recipient knows that handshake came from a legit user, but cannot cryptographically prove who signed the handshake in the ring.

The paper compares RINGxKEM to Signal's current handshake protocols (X3DH and PQXDH). While Signal's PQXDH effectively protects against Harvest-Now, Decrypt-Later (HNDL) attacks by combining a classical ECDH with a post-quantum KEM, it is provably unable to defend against User-State Compromise Impersonation (USCI), which means if an attacker steals a user's long-term private key, they can impersonate that user. RINGxKEM fixes this by using ring signatures, making impersonation impossible even if the long-term key is stolen, because the attacker cannot forge a valid ring signature without being part of the chosen group. To formally analyze this, the authors introduce a new framework called Bundled Authentication Key Exchange (BAKE), specifically designed to model how Signal's "bundled prekeys" (multiple public keys published at once) actually behave in practice. They use BAKE to benchmark X3DH, PQXDH, and the fully post-quantum RINGxKEM.

It is also important to note that RINGxKEM provides full forward secrecy: even if all long-term keys are compromised in the future, past session keys remain secure.

# This Implementation

This is a small demo of the protocol in rust. Currently uses a basic merkle tree, Abe-Okhubo-Suzki (AOS) ring sigs, prekey auth, AEAD encryption and session key derivation.

# How to Run

```bash
cargo run
```
