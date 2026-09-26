// Write a solana-test-validator --account file that puts a Token-2022 mint with 6 decimals at the real DREGG mint
// address, with the given mint authority, so local and CI validators can mint stand-in DREGG for the make fee.
//   node scripts/fake-dregg-mint.mjs <mint-authority-pubkey> <out.json>
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const web3 = require(path.join(here, "../web/node_modules/@solana/web3.js"));
const abi = require(path.join(here, "../web/abi.json"));
const [authority, out] = process.argv.slice(2);
const data = Buffer.alloc(82);
data.writeUInt32LE(1, 0); new web3.PublicKey(authority).toBuffer().copy(data, 4);   // mint authority: Some(authority)
data.writeBigUInt64LE(0n, 36);                                                        // supply
data[44] = abi.fee.make.decimals;                                                     // decimals
data[45] = 1;                                                                         // is_initialized
data.writeUInt32LE(0, 46);                                                            // freeze authority: None
fs.writeFileSync(out, JSON.stringify({ pubkey: abi.fee.make.mint, account: { lamports: 1461600, data: [data.toString("base64"), "base64"], owner: abi.programs.token_2022, executable: false, rentEpoch: 0, space: 82 } }));
console.log("wrote", out, "for mint", abi.fee.make.mint, "authority", authority);
