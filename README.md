# Anchor

Account security where the account address outlives its credentials.

## Problem
Losing or rotating a key usually means migrating to a new address. Anchor separates account identity from the authenticators and policies allowed to control it.

## How it works
- Identity: a WebAuthn P-256 passkey is registered on-chain with proof of possession (IdentityRegistry).
- Policy: authenticators and thresholds live in AuthConfigManager.
- Safe changes: policy changes are proposed, risk-scored by the contract, delayed 24h and contestable by a valid passkey. High-risk changes need extra confirmation.
- Transfer shield: transfers to new destinations are delayed and contestable.
- Guardians: a recovery-only authenticator role, registered on-chain and excluded from signing. Guardian-approved recovery is not implemented yet.

## Deployed on Monad testnet
- IdentityRegistry: 0xe92db7ed079aA6fF8888C6dD88f60C9Ed43De917
- AuthConfigManager: 0x8330D46baE39D554DaACc61c424F27fCf364919B
- AnchorViews: 0x08E2722d76fA8f964d88E44c202D3A3609c7A329

## Run
Frontend: cd frontend, npm install, npm run dev
Contracts: cd contracts, forge test
Set NEXT_PUBLIC_IDENTITY_REGISTRY, NEXT_PUBLIC_AUTH_CONFIG_MANAGER and NEXT_PUBLIC_ANCHOR_VIEWS in frontend/.env.local.
