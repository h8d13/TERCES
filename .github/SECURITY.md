# Security Model

## Why Hardware Keys?

Traditional password managers have a fundamental problem:

```
┌─────────────────────────────────────────────────────────┐
│                    CLOUD                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Encrypted(master_password, your_secrets)         │  │
│  │                      ↑                            │  │
│  │         Attacker steals this blob                 │  │
│  │         Brute force offline forever               │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**The LastPass breach (2022):** Attackers stole encrypted vaults from cloud storage. Every user with a weak master password is now compromised - attackers can guess billions of passwords per second offline, indefinitely.

**Terces model:**

```
┌─────────────────────────────────────────────────────────┐
│                    LOCAL ONLY                           │
│  ┌─────────────┐    ┌─────────────┐                     │
│  │ HardwareKey │ →  │ Derived Key │ → Decrypt           │
│  │ (required)  │    │ (ephemeral) │                     │
│  └─────────────┘    └─────────────┘                     │
│         ↑                                               │
│    PIN + Touch                                          │
│    8 attempts max                                       │
└─────────────────────────────────────────────────────────┘
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

### Terces approach: No recovery

- Lose your hardware key = lose access
- This is a feature, not a bug
- No backdoor means no backdoor for attackers either

### Mitigation

If you need redundancy:

1. **Register multiple hardware keys** during setup
2. **Store backup key** in physical safe / safety deposit box
3. **Never** create digital backups of secrets

---

## What Terces Does NOT Protect Against

- **Physical compromise** of your machine while unlocked
- **Root/admin malware** actively running during decryption
- **Compromise of the hardware key itself** (supply chain, firmware)
- **You** being coerced into unlocking or making mistakes originally

No tool protects against all threats. Understand your threat model.

---

## Recommendations

1. **Use a strong PIN** - 8 attempts is your buffer
2. **Enable FDE** - full disk encryption on your system

As Artix user/maintainer posted once in [post]() on a forum LemonPie

> *

3. **Multiple keys** - backup hardware key in secure location
4. **Air-gapped backup** - if critical, decrypt to offline storage that is contained

---

## Reporting Vulnerabilities

Open an issue or contact maintainer directly.

Security is to be taken seriously but this is a **personal** project reverse engineering `CTAP2` protocol.
