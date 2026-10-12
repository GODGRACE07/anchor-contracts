#!/usr/bin/env bash
RPC="https://testnet-rpc.monad.xyz"
REGISTRY="0xE17A65Aa009F1Bb3263A5B1bD0A8db397Fd3780d"
FROM="0x26fe2a0036c48e0e1e87a449b448f75773c38c43"
DATA="$1"
[ -z "$DATA" ] && { echo "Usage: bash diagnose.sh 0x<calldata>"; exit 1; }

echo "== 1. Selector sent by frontend (expected 0xdad67466) =="
echo "${DATA:0:10}"
echo; echo "== 2. Code size at registry =="
cast code "$REGISTRY" --rpc-url "$RPC" | wc -c
echo; echo "== 3. Selector present on-chain? =="
cast code "$REGISTRY" --rpc-url "$RPC" | grep -qi "${DATA:2:8}" && echo YES || echo "NO -> outdated deployment"
echo; echo "== 4. Simulated call (revert reason) =="
cast call "$REGISTRY" --data "$DATA" --from "$FROM" --rpc-url "$RPC" 2>&1 | head -20
echo; echo "== 5. Gas estimate =="
cast estimate "$REGISTRY" --data "$DATA" --from "$FROM" --rpc-url "$RPC" 2>&1 | head -5
echo; echo "== 6. Registry address in frontend =="
grep -rIn --exclude-dir=node_modules --exclude-dir=.next -i "e17a65" ~/anchor/frontend 2>/dev/null | head -10
echo; echo "== 7. P256 verifier approach =="
grep -rn "0x100\|precompile\|staticcall" ~/anchor/contracts/src ~/anchor/contracts/P256Verifier.sol 2>/dev/null | head -10
