# Security Model

## Why Hardware Keys?

Traditional password managers have a fundamental problem:

```
┌─────────────────────────────────────────────────────────┐
│                    CLOUD                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Encrypted(master_password, your_secrets)         │  │
│  │                      ↑                            │  │
│  │         Attacker steals this blob or cloud infra  │  │
│  │         Pawned offline forever                    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**The LastPass breach (2022):** Attackers stole encrypted vaults from cloud storage. Every user with a weak master password is now compromised - attackers can guess billions of passwords per second offline, indefinitely.

On the other hand, when you control when a device is on - interacting with lambda other device only if **necessary** and in a predefined way, is when the you get back control over your own privacy and sharing sensitive information. 

**Terces model:**

```
┌─────────────────────────────────────────────────────────┐
│                    LOCAL ONLY                           │
│  ┌─────────────┐    ┌─────────────┐                     │
│  │ HardwareKey │ →  │ Derived Key │ → Local features    │
│  │ (required)  │    │ (ephemeral) │   External Features │
│  └─────────────┘    └─────────────┘                     │
│         ↑                                               │
│    PIN + Touch + (Bio)                                  │
│    8 attempts max                                       │ → [KEY PROVDER SERVICES = HIGHER TRUST]
└─────────────────────────────────────────────────────────┘   [ ̶V̶e̶r̶s̶u̶s̶ ̶s̶o̶m̶e̶ ̶w̶e̶i̶r̶d̶ ̶U̶I̶ ̶f̶o̶r̶ ̶k̶e̶y̶ ̶m̶n̶g̶.̶.̶.̶]
```

No cloud. **No vault to steal.** Can't brute force without physical device and even then only has 8 tries.

Still allows for sharing using asymetric modules or controlled sharing of keys.

---

## Recovery Mechanisms = Security Threat

Every recovery option is an attack vector:

>[!TIP]
> The better approach is to set priorities in the actual services themselves major providers all have this (Google, Github, etc...).
> The second is to buy two keys (or more...) or get them sent to you by the manufacturing brands (please.)

| Recovery Method | Attack Vector |
|:----------------|:--------------|
| Email reset | Compromised email = compromised vault |
| SMS codes | SIM swapping, SS7 attacks |
| Security questions | Social engineering, public info |
| Recovery keys | Stored somewhere = can be stolen |
| Support reset | Social engineering support staff |

**The paradox:** The easier it is to recover, the easier it is to compromise.

### Terces approach: 

No recovery

- Lose your hardware key = lose access
- This is a feature, not a bug
- No backdoor means no backdoor for attackers either

### Mitigation

If you need redundancy:

1. **Register multiple hardware keys** during setup
2. **Store a backup key** in physical safe / safety deposit box
3. **Never** create digital backups of should-have-been-local secrets, 
4. **Do share** important information in fully private ways

---

## What Terces Does NOT Protect Against

- **Physical compromise** of your machine while unlocked
- **Root/admin malware** actively running during decryption
- **Compromise of the hardware key itself** (supply chain, firmware)
- **You** being coerced into unlocking or making mistakes originally

No tool protects against all threats. Understand your threat model or how much you need out of Terces features.
There are also many general good practices to do that can be found on many sites, forums, etc

---

## Recommendations

1. **Use a strong PIN** - 8 attempts is your buffer and the "attacker's"
2. **Enable FDE** - full disk encryption on your system (especially laptops)
3. **Multiple keys** - backup hardware key in secure location
4. **Air-gapped backup** - if critical, decrypt to offline storage that is contained

---

## Reporting Vulnerabilities

Open an issue (even for bugs, since it's hard to test other than what we have in [place](tests/)) or contact maintainer directly.

Security is to be taken seriously but this is a **personal** project reverse engineering `CTAP2` protocol.
