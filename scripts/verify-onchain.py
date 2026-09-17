#!/usr/bin/env python3
"""Check one deployments/<env>/config.yaml against the chains it names.

This is the CI counterpart of xarb-infra-contracts' publish tool. That tool
verifies from the deployment ledgers; those never leave the machine that
deployed, so this script works from the address book alone:

  - every listed contract has code on its chain
  - hub and spoke diamonds route exactly the selectors the artifacts manifests
    declare, and each facet's code, with its library link slots zeroed, hashes
    to the manifest's runtimeCodeHashUnlinked
  - spoke wiring (lendingPool, escrowVault, hub) and batch inbox destinations
    match the file
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


def parse_list(value: str) -> list[str]:
    return [item.strip() for item in value.strip("[]").split(",") if item.strip()]


def verify_diamond(label: str, chain: Chain, address: str, manifest: dict) -> None:
    facets = parse_list(chain.call(address, "facetAddresses()(address[])"))
    if len(facets) != len(manifest["facets"]):
        raise Failure(f"{label}: chain has {len(facets)} facets, manifest lists {len(manifest['facets'])}")
    for facet in manifest["facets"]:
        first = facet["functions"][0]["selector"]
        facet_address = chain.call(address, "facetAddress(bytes4)(address)", first)
        if int(facet_address, 16) == 0:
            raise Failure(f"{label}: {facet['name']} selector {first} is not routed")
        routed = set(parse_list(chain.call(address, "facetFunctionSelectors(address)(bytes4[])", facet_address)))
        expected = {item["selector"] for item in facet["functions"]}
        if routed != expected:
            raise Failure(f"{label}: {facet['name']} routing differs from the manifest by {sorted(routed ^ expected)}")
        if masked_hash(chain.code(facet_address), facet["linkReferences"]) != facet["runtimeCodeHashUnlinked"]:
            raise Failure(f"{label}: {facet['name']} at {facet_address} is not the manifest's build")
    print(f"  {label}: {len(facets)} facets, {sum(len(f['functions']) for f in manifest['facets'])} selectors, code matches the manifest")


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
    if data.get("schema_version") != 2:
        raise Failure("on-chain verification needs schema_version 2 (artifacts with manifests)")
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
            if name == "faucet_address":
                continue
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

    print("on-chain verification passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
