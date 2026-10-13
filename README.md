# Anchor

**Your account should outlive your credentials.**

Anchor is a passkey-based account-security layer on Monad. The account address never changes, while the authenticators and policies allowed to control it can be added, removed and reconfigured through changes that are risk-scored on-chain, delayed, and contestable.

Built for Monad Metropolis, Track 4: Trust, Identity & AI Infrastructure.

| | |
|---|---|
| Live demo (30s / 15s delays) | https://anchor-demo-eight.vercel.app |
| Contracts | https://github.com/GODGRACE07/anchor-contracts |
| Frontend | https://github.com/GODGRACE07/anchor-frontend |
| Network | Monad testnet (chain ID 10143) |

---

## Why this exists

Account compromise in 2026 keeps bypassing the private key itself.

- **Bitget, September 2026.** Reported at $351.6M when first disclosed, later revised upward. Bitget's CEO said the funds moved through spoofed transfers after a backend compromise, not through stolen private keys. The failure was in how authorization was approved, not in a key.
- **Fake GIWA bridge, late September 2026.** About $2M in ETH (766 ETH from roughly 1,300 wallets) was drained after a fake chain reused GIWA's real chain ID and a DEX treated it as GIWA's mainnet. Users sent funds to a destination nobody had verified.

Both are context for the threat model. Anchor does not claim to prevent every attack.

## The Monad proposal behind it

In August 2026, Monad researchers (Kushal Babel and Jan Camenisch) published the MIP **"Flexible and Upgradeable Account Authentication"** on the Monad Research Forum:
https://forum.monad.xyz/t/flexible-and-upgradeable-account-authentication/526

The proposal separates an account's identity from the authentication methods and policies authorized to control it, so keys can be rotated and new schemes (passkeys, and later post-quantum signatures) adopted without moving to a new address. Its configuration component is called `AuthConfigManager`.

Anchor is an independent, application-layer implementation of that model on testnet. It follows the same separation and uses the same `AuthConfigManager` name. It is not an official implementation, and the delay window, risk scoring and transfer shield are Anchor's own additions on top of the proposal.

---

## What Anchor does

1. **Passkey identity.** A real WebAuthn P-256 passkey is created in the browser and registered on-chain with a proof of possession. No seed phrase exists for Anchor to hold or leak.
2. **Policy engine.** Authenticators, signing policy and reconfiguration policy (with thresholds) live in `AuthConfigManager`, keyed by the account address.
3. **Risk-scored, delayed, contestable changes.** Every policy change is proposed with a passkey signature, scored by the contract, held for a delay window, and cancellable by a valid passkey. High-risk proposals require an extra confirmation before they can activate.
4. **Guardians.** A guardian is a registered authenticator (scheme 2) that is excluded from signing and reconfiguration policies. It shows up in on-chain state and in the UI.
5. **Transfer shield.** Payments to a destination the account has not used before are queued and contestable. Previously used destinations execute immediately.
6. **Security ledger.** The activity page reads contract events straight from the chain over RPC. There is no backend in the trust path.

### How a change flows

```
passkey signs proposal  ->  contract verifies WebAuthn proof on-chain
        |
        v
risk score computed on-chain (6 inputs)  ->  pending change + delay window
        |
        +--> any valid passkey can CONTEST  -> pending change deleted
        |
        +--> (high risk) extra confirmation required
        |
        v
delay elapsed  ->  ACTIVATE  ->  new policy live, same account address
```

Risk inputs: timestamp, time since last activity, whether the device pattern is known, recent failed attempts (contests count), reconfiguration threshold weakened, and authenticators removed.

---

## Contracts

| Contract | Role |
|---|---|
| `IdentityRegistry` | Registers P-256 passkey identities with a proof of possession (raw signature path and WebAuthn path) |
| `AuthConfigManager` | Policy, thresholds, propose / contest / confirm / activate, shielded transfers, WebAuthn variants of each write |
| `AnchorViews` | Read-only aggregator that joins identity, config and risk data for the frontend |
| `P256Verifier`, `WebAuthnVerifier`, `RiskScoring` | Libraries compiled into the above. WebAuthn verification rebuilds the signed payload from authenticatorData and clientDataJSON |

### Two builds, same code

Only two constants differ.

| | Production configuration | Judge demo |
|---|---|---|
| Reconfiguration delay | 24 hours | 30 seconds |
| Transfer delay | 1 hour | 15 seconds |
| IdentityRegistry | `0xe92db7ed079aA6fF8888C6dD88f60C9Ed43De917` | `0x8d586e1b1735cd6a457933cc586e1aa4c39bb33c` |
| AuthConfigManager | `0x8330D46baE39D554DaACc61c424F27fCf364919B` | `0xb03854b2a0c074e67206e61cb3ce992129f87d3d` |
| AnchorViews | `0x08E2722d76fA8f964d88E44c202D3A3609c7A329` | `0x54c7f70dc4deffea9ed08ffeb4ffac0ef0969ea3` |
| Contracts branch | `main` | `demo-short-delays` (default) |

The delay is meant to give a victim time to contest. The 30-second build exists only so a reviewer can watch a full cycle in a minute. The frontend repository is configured for the demo build: its copy says 30 seconds and 15 seconds, and `lib/anchor.ts` falls back to older addresses if the environment variables are missing.

---

## Try it in 3 minutes

You need a browser wallet (OKX Wallet or MetaMask) on Monad testnet and a little testnet MON.

**Wallet network:** name `Monad Testnet`, RPC `https://testnet-rpc.monad.xyz` (backup `https://monad-testnet.drpc.org`), chain ID `10143`, symbol `MON`, explorer `https://testnet.monadscan.com`. Faucet: https://www.alchemy.com/faucets/monad-testnet

Use **one browser profile for the whole flow**, and keep only one wallet extension enabled. Passkeys are bound to the site's domain, and the app remembers the credential ID in that browser.

1. Open the live demo and click **Connect**.
2. `/identity`: **Create passkey**, then **Initialize Anchor policy**.
3. `/policy`: under "Need another device?" name a passkey and click **Add**. Choose **Guardian (recovery only)**, click **Include passkey**, then **Stage this policy change**. Approve with your first passkey.
4. Watch the risk score and the 30-second window. **Activate** stays locked until the delay passes, then unlocks.
5. `/guardians` shows one configured and one active guardian. `/console` shows two authenticators.
6. `/shield`: deposit 0.01 MON, send a small amount to an address you have never used. It goes pending. Wait 15 seconds and activate it, or contest it and the funds stay put.

---

## Tests

```bash
cd contracts
forge test
```

52 tests across 11 suites pass. `foundry.toml` pins `evm_version = "osaka"` so the local EVM provides the P-256 precompile. These run on a local EVM, not against testnet.

Frontend: `npx tsc --noEmit`, `npx eslint .` and `npm run build` all pass.

## Run locally

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_IDENTITY_REGISTRY`, `NEXT_PUBLIC_AUTH_CONFIG_MANAGER` and `NEXT_PUBLIC_ANCHOR_VIEWS` in `frontend/.env.local`.

---

## Limitations (stated plainly)

- **Guardian-approved recovery is not implemented.** A guardian is a registered, recovery-only role that cannot sign or change policy. The contract has no recovery function yet.
- The judge demo uses shortened delays. Production configuration is 24 hours and 1 hour.
- Tests run on a local EVM with the P-256 precompile, not on testnet.
- Passkeys are tied to the domain they were created on, so a passkey made on `localhost` will not sign on the deployed site.
- Credential IDs are kept in the browser's local storage. Clearing storage means that browser can no longer sign with that passkey.
- No external audit. This is hackathon software on testnet.

## Roadmap

1. Guardian-approved recovery with an approval threshold, a delay and a contest path.
2. Event indexing so the security ledger loads full history instead of a recent block window.
3. Contract verification on MonadScan and a security review.

## Sources

- Monad MIP, "Flexible and Upgradeable Account Authentication": https://forum.monad.xyz/t/flexible-and-upgradeable-account-authentication/526
- Bitget incident: BleepingComputer, The Hacker News, CoinDesk (September 2026)
- Fake GIWA chain incident: Cointelegraph, Crypto Economy (September 2026)
