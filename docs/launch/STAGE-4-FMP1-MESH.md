# Stage 4 Launch Kit — `eyeoverthink/fmp1-mesh` (`v1.0.0`)

- **Target Communities:** `r/selfhosted`, `r/meshtastic`, `r/raspberry_pi`, Show HN
- **Repo & Release:** https://github.com/eyeoverthink/fmp1-mesh
- **License:** Apache-2.0

---

## 1. Title Options (Anti-Hype, Concrete Scope)

- **Show HN:** `Show HN: FMP/1 – Authenticated CBOR/UDP mesh prototype with custody, replay windows, and Pi systemd unit`
- **r/selfhosted / r/meshtastic:** `Open-sourced FMP/1: a Python UDP/LoRa-profile mesh protocol with Ed25519/ChaCha20-Poly1305, store-and-forward custody, and a 6-node loopback simulator`

---

## 2. 15-Second Verification Block (127.0.0.1 Only, No Hardware Required)

```bash
git clone https://github.com/eyeoverthink/fmp1-mesh && cd fmp1-mesh
python3 -m venv venv && . venv/bin/activate
pip install -e .[test]
pytest -q                                  # 48 tests (~15 s)
fmp1 sim --nodes 6 --loss 0.05 --seed 7    # 10 scenarios: 5-hop loss, 5KB SACK/NACK, partition custody, security rejections
```

---

## 3. What Makes It Technically Interesting

- **Minimal dependency footprint:** Python stdlib + `cryptography` only (includes its own strict RFC 8949 CBOR codec with bounded depth).
- **Real mesh & DTN mechanics, not a toy chat script:**
  - 48-byte wire header (plus a 19-byte compact LoRa profile)
  - Ed25519 + X25519 + ChaCha20-Poly1305 E2E encryption (with `--amateur` mode that refuses encryption for FCC §97.113(a)(4) ham links)
  - IPsec-style 64-entry replay window + 30-min `msg_id` dedupe + DSDV/ETX routing with poison reverse
  - 5 KB fragmentation with SACK/NACK repair, store-and-forward `CUSTODY` across partitions, Trickle flooding + Bloom `DIGEST/REQUEST` anti-entropy
  - Dual-key `INTENT` gating (`commander` + `approver` countersignature, recorded as `approved_pending_operator` and **never auto-executed**)
- **No-RTC clock honesty + `SVA-ER/1` export:** Raspberry Pi nodes without a battery-backed RTC export their hash-chained `receipts.jsonl` via `fmp1 export-sva` with `clock.status = "unattested"` by default, verifiable offline with `npx @eyeoverthink/ai-receipt verify`.

---

## 4. Honest Limits (State Upfront)

- **Prototype — do not use for life-safety messaging.** Community notices force a non-official banner and reject AMBER/EAS/WEA/IPAWS branding.
- No live LoRa radio bridge yet (compact codec exists; transport runs over IPv4 UDP/loopback/LAN/WireGuard/batman-adv).
- Static X25519 E2E (no forward secrecy); Python-level throughput (hundreds of packets/s); not externally security-audited.
