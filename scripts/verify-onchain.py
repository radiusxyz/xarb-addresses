#!/usr/bin/env python3
"""Check one deployments/<env>/config.yaml against the chains it names.

This is the CI counterpart of xarb-infra-contracts' publish tool. That tool
verifies from the deployment ledgers; those never leave the machine that
deployed, so this script works from the address book alone:

  - every listed contract has code on its chain
  - hub and spoke diamonds route exactly the selectors the artifacts manifests
    declare, and each facet's code, with its deployment-address slots zeroed,
    hashes to the manifest's runtimeCodeHashUnlinked
  - every external library a facet links, found through the facet's link
    slots, hashes to the manifest's entry the same way
  - the LendingPool and EscrowVault implementations behind their proxies hash
    to the manifest's entries
  - spoke wiring (lendingPool, escrowVault, hub) and batch inbox destinations
    match the file
  - spoke tokens are exactly the LendingPool's getReservesList(), in order, and
    each token's decimals() matches (symbol() is compared ignoring case: the
    file carries the ledger's canonical symbol)
  - the faucet's tokens()/amounts()/nativeAmount() match the file; owner() and
    operator() only warn when they differ, since the owner can change them
    without a republish and they do not affect what the faucet dispenses
  - when routes.yaml is present, every propagator route is registered on its
    inbox with exactly the source, destination and genesis block the file says
  - when two RPC endpoints are configured for a chain, both must agree

Reads are pinned to a block a few behind the head so a lagging endpoint or a
shallow reorg does not fail the run.

Usage:
    verify-onchain.py deployments/staging/config.yaml [--rpc 84532=https://... ...] [--confirmations 2]

RPC endpoints come from --rpc, else XARB_RPC_<chainId> / XARB_RPC_<chainId>_B in
the environment, else environments.yaml chains.<id>.rpc_urls.
Requires cast (foundry) and pyyaml.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


class Failure(Exception):
    pass


def cast(*args: str) -> str:
    result = subprocess.run(["cast", *args], capture_output=True, text=True, env={**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"})
    if result.returncode != 0:
        raise Failure(f"cast {' '.join(args[:3])}…: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


class Chain:
    def __init__(self, chain_id: int, urls: list[str], confirmations: int):
        self.chain_id = chain_id
        self.urls = urls
        for url in urls:
            reported = int(cast("chain-id", "--rpc-url", url))
            if reported != chain_id:
                raise Failure(f"{url} serves chain {reported}, expected {chain_id}")
        self.block = max(min(int(cast("block-number", "--rpc-url", u)) for u in urls) - confirmations, 0)

    def call(self, target: str, signature: str, *args: str) -> str:
        answers = {cast("call", target, signature, *args, "--rpc-url", url, "--block", str(self.block)) for url in self.urls}
        if len(answers) != 1:
            raise Failure(f"RPC endpoints for chain {self.chain_id} disagree on {signature} at block {self.block}")
        return answers.pop()

    def code(self, target: str) -> str:
        answers = {cast("code", target, "--rpc-url", url, "--block", str(self.block)) for url in self.urls}
        if len(answers) != 1:
            raise Failure(f"RPC endpoints for chain {self.chain_id} disagree on code of {target}")
        return answers.pop()


def keccak(data: bytes) -> str:
    return cast("keccak", "0x" + data.hex())


def masked_hash(code_hex: str, references: list[dict]) -> str:
    buffer = bytearray(bytes.fromhex(code_hex[2:]))
    for reference in references:
        buffer[reference["start"]:reference["start"] + reference["length"]] = b"\0" * reference["length"]
    return keccak(bytes(buffer))


IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def artifact_entry(manifest: dict, name: str) -> dict:
    for entry in manifest["sizeArtifacts"]:
        if entry["artifact"].split(":")[1] == name:
            return entry
    raise Failure(f"manifest has no sizeArtifacts entry for {name}")


def linked_libraries(code_hex: str, ranges: list[dict]) -> set[str]:
    code = bytes.fromhex(code_hex[2:])
    return {"0x" + code[r["start"]:r["start"] + 20].hex() for r in ranges if r["length"] == 20}


def verify_code(label: str, chain: Chain, address: str, entry: dict) -> None:
    code = chain.code(address)
    if code == "0x":
        raise Failure(f"{label} {address} has no code")
    if masked_hash(code, entry["maskedRanges"]) != entry["runtimeCodeHashUnlinked"]:
        raise Failure(f"{label} at {address} is not the manifest's build of {entry['artifact'].split(':')[1]}")


def verify_implementation(label: str, chain: Chain, proxy: str, manifest: dict, name: str) -> None:
    word = cast("storage", proxy, IMPLEMENTATION_SLOT, "--rpc-url", chain.urls[0], "--block", str(chain.block))
    implementation = "0x" + word[-40:]
    if int(implementation, 16) == 0:
        raise Failure(f"{label} {proxy} has no implementation in the ERC-1967 slot")
    entry = artifact_entry(manifest, name)
    verify_code(f"{label} implementation", chain, implementation, entry)
    print(f"  {label}: implementation {implementation} is the manifest's {name}")
    libraries = {address: {name} for address in linked_libraries(chain.code(implementation), entry["maskedRanges"])}
    verify_libraries(label, chain, libraries, manifest)


def parse_list(value: str) -> list[str]:
    return [item.strip() for item in value.strip("[]").split(",") if item.strip()]


def verify_diamond(label: str, chain: Chain, address: str, manifest: dict) -> None:
    facets = parse_list(chain.call(address, "facetAddresses()(address[])"))
    if len(facets) != len(manifest["facets"]):
        raise Failure(f"{label}: chain has {len(facets)} facets, manifest lists {len(manifest['facets'])}")
    libraries: dict[str, set[str]] = {}
    for facet in manifest["facets"]:
        first = facet["functions"][0]["selector"]
        facet_address = chain.call(address, "facetAddress(bytes4)(address)", first)
        if int(facet_address, 16) == 0:
            raise Failure(f"{label}: {facet['name']} selector {first} is not routed")
        routed = set(parse_list(chain.call(address, "facetFunctionSelectors(address)(bytes4[])", facet_address)))
        expected = {item["selector"] for item in facet["functions"]}
        if routed != expected:
            raise Failure(f"{label}: {facet['name']} routing differs from the manifest by {sorted(routed ^ expected)}")
        code = chain.code(facet_address)
        if masked_hash(code, facet["maskedRanges"]) != facet["runtimeCodeHashUnlinked"]:
            raise Failure(f"{label}: {facet['name']} at {facet_address} is not the manifest's build")
        for library in linked_libraries(code, facet["maskedRanges"]):
            libraries.setdefault(library, set()).add(facet["name"])
    print(f"  {label}: {len(facets)} facets, {sum(len(f['functions']) for f in manifest['facets'])} selectors, code matches the manifest")
    verify_libraries(label, chain, libraries, manifest)


def verify_libraries(label: str, chain: Chain, libraries: dict[str, set[str]], manifest: dict) -> None:
    entries = [e for e in manifest["sizeArtifacts"] if any(l["artifact"] == e["artifact"] for l in manifest["libraries"])]
    matched = 0
    for address in sorted(libraries):
        code = chain.code(address)
        if code == "0x":
            raise Failure(f"{label}: library {address} linked by {sorted(libraries[address])} has no code")
        digest = None
        for entry in entries:
            if masked_hash(code, entry["maskedRanges"]) == entry["runtimeCodeHashUnlinked"]:
                digest = entry["artifact"].split(":")[1]
                break
        if digest is None:
            raise Failure(f"{label}: library {address} linked by {sorted(libraries[address])} matches no library in the manifest")
        matched += 1
    print(f"  {label}: {matched} linked libraries match the manifest")


def unquote(value: str) -> str:
    return value.strip().strip('"')


def verify_tokens(label: str, chain: Chain, pool: str, tokens: list[dict]) -> None:
    reserves = [item.lower() for item in parse_list(chain.call(pool, "getReservesList()(address[])"))]
    listed = [token["address"].lower() for token in tokens]
    if reserves != listed:
        raise Failure(f"{label}: lending_pool reserves are {reserves}, file lists {listed}")
    for token in tokens:
        require_code(f"{label}.tokens.{token['symbol']}", chain, token["address"])
        symbol = unquote(chain.call(token["address"], "symbol()(string)"))
        if symbol.lower() != token["symbol"].lower():
            raise Failure(f"{label}: token {token['address']} is {symbol} on chain, file says {token['symbol']}")
        decimals = int(chain.call(token["address"], "decimals()(uint8)"))
        if decimals != token["decimals"]:
            raise Failure(f"{label}: token {token['symbol']} has {decimals} decimals, file says {token['decimals']}")
    print(f"  {label}: {len(tokens)} tokens match the lending_pool reserves")


def verify_faucet(label: str, chain: Chain, faucet: dict, tokens: list[dict]) -> None:
    address = faucet["address"]
    require_code(f"{label}.faucet", chain, address)
    by_symbol = {token["symbol"]: token["address"].lower() for token in tokens}
    expected_tokens = [by_symbol[drip["token"]] for drip in faucet["drips"]]
    expected_amounts = [drip["amount"] for drip in faucet["drips"]]
    on_chain_tokens = [item.lower() for item in parse_list(chain.call(address, "tokens()(address[])"))]
    on_chain_amounts = [item.split(" ")[0] for item in parse_list(chain.call(address, "amounts()(uint256[])"))]
    if on_chain_tokens != expected_tokens:
        raise Failure(f"{label}.faucet: tokens() is {on_chain_tokens}, file drips {expected_tokens}")
    if on_chain_amounts != expected_amounts:
        raise Failure(f"{label}.faucet: amounts() is {on_chain_amounts}, file says {expected_amounts}")
    native = chain.call(address, "nativeAmount()(uint256)").split(" ")[0]
    if native != faucet["native_amount"]:
        raise Failure(f"{label}.faucet: nativeAmount() is {native}, file says {faucet['native_amount']}")
    for view in ("owner", "operator"):
        actual = chain.call(address, f"{view}()(address)")
        if actual.lower() != faucet[view].lower():
            print(f"  warn {label}.faucet: {view}() is {actual}, file says {faucet[view]} (stale snapshot; republish to refresh)")
    print(f"  {label}.faucet: {len(faucet['drips'])} drips and native amount match the chain")


def require_code(label: str, chain: Chain, address: str) -> None:
    if chain.code(address) == "0x":
        raise Failure(f"{label} {address} has no code on chain {chain.chain_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config")
    parser.add_argument("--rpc", action="append", default=[], help="<chainId>=<url>; repeatable, two per chain to cross-check")
    parser.add_argument("--confirmations", type=int, default=2)
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    env_dir = config_path.parent
    data = yaml.safe_load(config_path.read_text())
    if "artifacts" not in data:
        raise Failure("on-chain verification needs the artifacts block (manifests)")
    environments = yaml.safe_load((ROOT / "environments.yaml").read_text())

    rpc_urls: dict[int, list[str]] = {}
    for item in args.rpc:
        chain_id, url = item.split("=", 1)
        rpc_urls.setdefault(int(chain_id), []).append(url)
    needed = {data["hub"]["chain_id"], *(s["chain_id"] for s in data["spokes"])}
    for chain_id in needed:
        if chain_id in rpc_urls:
            continue
        from_env = [os.environ.get(f"XARB_RPC_{chain_id}"), os.environ.get(f"XARB_RPC_{chain_id}_B")]
        urls = [u for u in from_env if u] or list(environments["chains"].get(chain_id, {}).get("rpc_urls", []))
        if not urls:
            raise Failure(f"no RPC for chain {chain_id}: pass --rpc {chain_id}=<url> or set XARB_RPC_{chain_id}")
        rpc_urls[chain_id] = urls
    chains = {chain_id: Chain(chain_id, urls, args.confirmations) for chain_id, urls in rpc_urls.items() if chain_id in needed}
    for chain_id, chain in chains.items():
        print(f"chain {chain_id}: {len(chain.urls)} endpoint(s), reading at block {chain.block}")

    manifests = {
        "hub": json.loads((env_dir / data["artifacts"]["hub_manifest"]["path"]).read_text()),
        "spoke": json.loads((env_dir / data["artifacts"]["spoke_manifest"]["path"]).read_text()),
    }

    hub = data["hub"]
    chain = chains[hub["chain_id"]]
    contracts = {name: entry["address"] for name, entry in hub["contracts"].items()}
    for name, address in contracts.items():
        require_code(f"hub.{name}", chain, address)
    verify_diamond("hub", chain, contracts["hub"], manifests["hub"])
    if "batch_inbox" in contracts:
        destination = chain.call(contracts["batch_inbox"], "destination()(address)")
        if destination.lower() != contracts["hub"].lower():
            raise Failure(f"hub batch_inbox destination is {destination}, not the hub")

    for spoke in data["spokes"]:
        chain = chains[spoke["chain_id"]]
        label = f"spoke[{spoke['chain_id']}]"
        contracts = {name: entry["address"] for name, entry in spoke["contracts"].items()}
        for name, address in contracts.items():
            require_code(f"{label}.{name}", chain, address)
        for view, key in (("lendingPool()(address)", "lending_pool"), ("escrowVault()(address)", "escrow_vault")):
            actual = chain.call(contracts["spoke"], view)
            if actual.lower() != contracts[key].lower():
                raise Failure(f"{label}.{view} returns {actual}, file says {contracts[key]}")
        wired_hub = chain.call(contracts["spoke"], "hub()(address)")
        if wired_hub.lower() != hub["contracts"]["hub"]["address"].lower():
            raise Failure(f"{label} is wired to hub {wired_hub}, file says {hub['contracts']['hub']['address']}")
        if "batch_inbox" in contracts:
            destination = chain.call(contracts["batch_inbox"], "destination()(address)")
            if destination.lower() != contracts["spoke"].lower():
                raise Failure(f"{label} batch_inbox destination is {destination}, not the spoke")
        verify_diamond(label, chain, contracts["spoke"], manifests["spoke"])
        verify_implementation(f"{label}.lending_pool", chain, contracts["lending_pool"], manifests["spoke"], "LendingPool")
        verify_implementation(f"{label}.escrow_vault", chain, contracts["escrow_vault"], manifests["spoke"], "EscrowVault")
        if "tokens" in spoke:
            verify_tokens(label, chain, contracts["lending_pool"], spoke["tokens"])
        if "faucet" in spoke:
            if "tokens" not in spoke:
                raise Failure(f"{label}.faucet needs the spoke's tokens list")
            verify_faucet(label, chain, spoke["faucet"], spoke["tokens"])

    routes_path = env_dir / "routes.yaml"
    if routes_path.is_file():
        routes = yaml.safe_load(routes_path.read_text()) or {}
        for route in routes.get("xarb_propagator_routes", []):
            chain = chains[int(route["destination_chain_id"])]
            registered = chain.call(route["inbox"], "routeRegistered(bytes32)(bool)", route["id"])
            if registered != "true":
                raise Failure(f"route {route['id']} is not registered on inbox {route['inbox']}")
            config = chain.call(route["inbox"], "routeConfig(bytes32)((uint32,address,uint32,address,uint64))", route["id"])
            fields = [f.strip().split(" ")[0].lower() for f in config.strip("()").split(",")]
            expected = [str(route["source_chain_id"]), route["source_contract"].lower(), str(route["destination_chain_id"]), route["destination_contract"].lower(), str(route["genesis_block"])]
            if fields != expected:
                raise Failure(f"route {route['id']} on {route['inbox']} is {fields} on chain, routes.yaml says {expected}")
        print(f"  routes: {len(routes.get('xarb_propagator_routes', []))} propagator routes registered on their inboxes with matching config")

    print("on-chain verification passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
