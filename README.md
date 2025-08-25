# Timestamped Vault

This repository is an **archive of timestamped artifacts**.  
Each entry contains:

- **SHA-256 digest** (`.sha256`) of the original data  
- **OpenTimestamps proof** (`.ots`) binding that digest to a verifiable point in time  

The vault holds **cryptographic proofs only** — not the underlying files. Its purpose is to provide tamper-resistant evidence that specific data existed at or before a given timestamp.

---

## Quick Verification (Web)

1. Visit **[opentimestamps.org](https://opentimestamps.org)**  
2. Upload both:  
   - The `.ots` file  
   - The corresponding `.sha256` file  
3. The site will validate the proof and display whether it has been anchored to the Bitcoin blockchain.

---

## Verification (CLI)

For local verification using the [OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client):

```bash
# Inspect the .ots file
ots info file.ots

# Verify the OpenTimestamps proof
ots verify file.ots
