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

## Schema v3: contract ABIs

`artifacts.abi` carries the ABI of every contract this deployment runs, copied
byte-for-byte from `xarb-infra-contracts` `config/abi/`. Off-chain components
read these instead of keeping their own copy, so an ABI change reaches them by
redeploying rather than by editing each repository.

Keys match a chain's `contracts` keys (`lending_pool`, `batch_inbox`,
`request_gateway`, ...) so an address and its ABI share a name. The set follows
`config/abi-exports.json` in the contracts repository and grows with the
protocol, so the schema leaves it open rather than enumerating it; it also holds
entries with no address of their own, such as the reserve token implementations.

`hub` and `spoke` are the merged diamond ABIs. CI checks their `sha256` against
the `abiSha256` the matching manifest pins, so a book cannot carry an ABI from a
different build than the manifest describes.

The block is optional: a book published before ABIs were carried stays valid.
When present it must hold at least `hub` and `spoke`.
