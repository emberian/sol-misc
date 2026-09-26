#!/bin/sh
# Fresh local validator for the passwap tests: keys, a Token-2022 mint A, a classic mint B, funded maker and payer,
# and a stand-in DREGG mint at the real DREGG address so makes can pay their 1000 DREGG fee.
#   sh scripts/localsetup.sh <state-dir>      (writes <state-dir>/{mintauth,maker,payer}.json, mints.txt; runs the validator in the background)
set -e
L=${1:?state dir}; mkdir -p "$L"; HERE=$(cd "$(dirname "$0")" && pwd)
U=http://127.0.0.1:8899
for k in mintauth maker payer; do [ -f "$L/$k.json" ] || solana-keygen new --no-bip39-passphrase --silent -o "$L/$k.json"; done
MINTAUTH=$(solana-keygen pubkey "$L/mintauth.json"); MAKER=$(solana-keygen pubkey "$L/maker.json"); PAYER=$(solana-keygen pubkey "$L/payer.json")
DREGG=$(node -e "console.log(require('$HERE/../web/abi.json').fee.make.mint)")
node "$HERE/fake-dregg-mint.mjs" "$MINTAUTH" "$L/dregg-mint.json"
pkill -x solana-test-validator 2>/dev/null || true; sleep 2
(nohup solana-test-validator --reset --quiet --ledger "$L/ledger" --mint "$MINTAUTH" --rpc-port 8899 --account "$DREGG" "$L/dregg-mint.json" >"$L/validator.log" 2>&1 &)
for i in $(seq 1 90); do curl -s -m 2 $U -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null | grep -q '"ok"' && break; sleep 1; done
solana airdrop 10 "$MAKER" -u $U >/dev/null; solana airdrop 10 "$PAYER" -u $U >/dev/null
MA=$(spl-token create-token --program-2022 --decimals 6 -u $U --fee-payer "$L/mintauth.json" --mint-authority "$L/mintauth.json" --output json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).commandOutput.address))")
MB=$(spl-token create-token --decimals 6 -u $U --fee-payer "$L/mintauth.json" --mint-authority "$L/mintauth.json" --output json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).commandOutput.address))")
spl-token create-account "$MA" --owner "$MAKER" -u $U --fee-payer "$L/mintauth.json" >/dev/null
spl-token mint "$MA" 4000000 --recipient-owner "$MAKER" -u $U --fee-payer "$L/mintauth.json" --mint-authority "$L/mintauth.json" >/dev/null
spl-token create-account "$MB" --owner "$PAYER" -u $U --fee-payer "$L/mintauth.json" >/dev/null
spl-token mint "$MB" 2000 --recipient-owner "$PAYER" -u $U --fee-payer "$L/mintauth.json" --mint-authority "$L/mintauth.json" >/dev/null
spl-token create-account "$DREGG" --owner "$MAKER" --program-2022 -u $U --fee-payer "$L/mintauth.json" >/dev/null
spl-token mint "$DREGG" 100000 --recipient-owner "$MAKER" --program-2022 -u $U --fee-payer "$L/mintauth.json" --mint-authority "$L/mintauth.json" >/dev/null
printf '%s\n%s\n' "$MA" "$MB" > "$L/mints.txt"
echo "validator up: mint A (2022) $MA | mint B $MB | DREGG stand-in $DREGG | maker $MAKER | payer $PAYER"
