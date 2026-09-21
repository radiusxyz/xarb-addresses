# xArb Addresses

Public deployment metadata for xArb contracts.

This repository contains contract addresses, chain IDs, deployment blocks, and related public metadata.
It does not contain RPC credentials, private keys, auth tokens, database URLs, or operational secrets.

## Schema v2: spoke tokens and faucet

Each spoke may carry two optional blocks the frontend and other consumers read
instead of hand-maintained inventory:

- `tokens`: the LendingPool's reserve tokens in `getReservesList()` order, with
  `symbol`, `address` and `decimals`. `symbol` is the canonical id from the
  contracts deployment ledger; the token's on-chain `symbol()` may differ in
  case and is only used as a verification hint.
- `faucet`: a snapshot of the chain's `FaucetDispenser` (`address`, `owner`,
  `operator`, `native_amount`, `drips`). `drips[].token` refers to a `symbol` in
  `tokens`, so a faucet can only dispense this deployment's tokens. Faucet
  amounts are on-chain state; the address book records what they were at
  publish time, and CI fails when `tokens()`, `amounts()` or `nativeAmount()`
  drift, while `owner`/`operator` drift only warns. Faucets are never published
  for `production`.

Hub entries carry neither block.
