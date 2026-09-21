#!/usr/bin/env python3
"""Validate every deployments/<env>/config.yaml against schemas/deployment.schema.json.

Beyond the JSON schema this checks what the schema cannot express:
  - the environment directory name matches the file's `environment`
  - every chain_id is allowed for that environment (environments.yaml)
  - chain name / native_symbol / explorer_url match environments.yaml
  - when artifacts are declared: every artifact exists under the environment directory and
    its digest matches (sha256 for JSON copies, keccak256 for manifests), and
    nothing sits under artifacts/ undeclared
  - when routes.yaml sits next to config.yaml: it carries the two route lists
    xarb-operations-infra reads, with the same ids on both sides, every route
    joining the hub and one of the spokes, propagator routes naming the
    destination chain's batch_inbox, and ids equal to
    keccak256(abi.encode(ROUTE_TYPEHASH, source, destination))

Usage:
    python3 scripts/validate-deployments.py [deployments/<env>/config.yaml ...]

Requires: pyyaml, jsonschema  (pip install pyyaml jsonschema rfc3339-validator)
keccak256 needs eth-hash or pysha3; without either, manifest digests are skipped
with a warning.
Exits non-zero if any config fails. Intended for local use and CI.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
    from jsonschema import FormatChecker
except ImportError as exc:  # pragma: no cover - dependency hint
    sys.exit(
        f"missing dependency: {exc.name}. "
        "Install with: pip install pyyaml jsonschema rfc3339-validator"
    )

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "deployment.schema.json"
ENVIRONMENTS_PATH = ROOT / "environments.yaml"
CONFIG_GLOB = "deployments/*/config.yaml"

# Directory names that map onto a logical environment in environments.yaml.
ENVIRONMENT_OF_DIRECTORY = {
    "dev-a": "dev",
    "dev-b": "dev",
    "dev-c": "dev",
    "dev-d": "dev",
    "staging": "staging",
    "production": "production",
}


def keccak256(data: bytes) -> str | None:
    try:
        from eth_hash.auto import keccak  # type: ignore

        return keccak(data).hex()
    except ImportError:
        pass
    try:
        import sha3  # type: ignore

        return sha3.keccak_256(data).hexdigest()
    except ImportError:
        return None


def check_environment(data: dict, directory: str, environments: dict) -> list[str]:
    errors = []
    logical = ENVIRONMENT_OF_DIRECTORY.get(directory)
    if logical is None:
        return [f"directory {directory} is not a known environment directory"]
    if data.get("environment") != logical:
        errors.append(f"environment: expected {logical} for directory {directory}, got {data.get('environment')}")
    allowed = set(environments["environments"].get(logical, {}).get("allowed_chain_ids", []))
    chains = environments["chains"]
    nodes = [("hub", data.get("hub", {}))]
    nodes += [(f"spokes/{i}", spoke) for i, spoke in enumerate(data.get("spokes", []))]
    for label, node in nodes:
        chain_id = node.get("chain_id")
        if chain_id not in allowed:
            errors.append(f"{label}/chain_id: {chain_id} is not allowed for {logical} (allowed: {sorted(allowed)})")
        meta = chains.get(chain_id)
        if meta is None:
            errors.append(f"{label}/chain_id: {chain_id} has no entry in environments.yaml chains")
            continue
        for key in ("name", "native_symbol", "explorer_url"):
            expected, actual = meta[key], node.get(key)
            if key == "explorer_url":
                expected, actual = expected.rstrip("/"), str(actual or "").rstrip("/")
            if actual != expected:
                errors.append(f"{label}/{key}: expected {meta[key]} for chain {chain_id}, got {node.get(key)}")
    return errors


ROUTE_TYPEHASH = "Route(uint32 sourceChainId,address sourceContract,uint32 destinationChainId,address destinationContract)"


def route_id(source_chain: int, source: str, destination_chain: int, destination: str) -> str | None:
    digest = keccak256(ROUTE_TYPEHASH.encode())
    if digest is None:
        return None
    encoded = bytes.fromhex(digest) + source_chain.to_bytes(32, "big") + bytes(12) + bytes.fromhex(source[2:]) \
        + destination_chain.to_bytes(32, "big") + bytes(12) + bytes.fromhex(destination[2:])
    return "0x" + keccak256(encoded)


def check_routes(data: dict, env_dir: Path) -> list[str]:
    path = env_dir / "routes.yaml"
    if not path.is_file():
        return []
    errors = []
    routes = yaml.safe_load(path.read_text()) or {}
    indexer = routes.get("xarb_indexer_routes")
    propagator = routes.get("xarb_propagator_routes")
    if not isinstance(indexer, list) or not indexer or not isinstance(propagator, list) or not propagator:
        return ["routes.yaml: xarb_indexer_routes and xarb_propagator_routes must both be non-empty lists"]

    hub = data["hub"]
    hub_key = (hub["chain_id"], hub["contracts"]["hub"]["address"].lower())
    spokes = {(s["chain_id"], s["contracts"]["spoke"]["address"].lower()): s for s in data["spokes"]}
    inbox_of = {hub_key: (hub["contracts"].get("batch_inbox") or {}).get("address", "").lower()}
    inbox_of.update({k: (s["contracts"].get("batch_inbox") or {}).get("address", "").lower() for k, s in spokes.items()})
    expected_pairs = set()
    for spoke_key in spokes:
        expected_pairs.add((hub_key, spoke_key))
        expected_pairs.add((spoke_key, hub_key))

    def endpoint(route: dict, label: str) -> tuple | None:
        try:
            src = (int(route["source_chain_id"]), str(route["source_contract"]).lower())
            dst = (int(route["destination_chain_id"]), str(route["destination_contract"]).lower())
        except (KeyError, ValueError, TypeError):
            errors.append(f"routes.yaml: {label} lacks source/destination chain and contract")
            return None
        return src, dst

    seen_pairs = set()
    for label, routes_list in (("indexer", indexer), ("propagator", propagator)):
        for index, route in enumerate(routes_list):
            where = f"{label} route {index}"
            rid = str(route.get("id", "")).lower()
            if not (rid.startswith("0x") and len(rid) == 66):
                errors.append(f"routes.yaml: {where} id must be a 32-byte hex string")
                continue
            pair = endpoint(route, where)
            if pair is None:
                continue
            if pair not in expected_pairs:
                errors.append(f"routes.yaml: {where} joins {pair[0]} -> {pair[1]}, which is not hub<->spoke in config.yaml")
            expected = route_id(pair[0][0], pair[0][1], pair[1][0], pair[1][1])
            if expected is not None and expected != rid:
                errors.append(f"routes.yaml: {where} id {rid} is not keccak of its endpoints ({expected})")
            if label == "propagator":
                seen_pairs.add(pair)
                if not str(route.get("name", "")).strip():
                    errors.append(f"routes.yaml: {where} needs a name")
                inbox = str(route.get("inbox", "")).lower()
                if not inbox or inbox != inbox_of.get(pair[1], ""):
                    errors.append(f"routes.yaml: {where} inbox {inbox or '<missing>'} is not the destination's batch_inbox in config.yaml")
                try:
                    if int(route.get("genesis_block", 0)) <= 0:
                        errors.append(f"routes.yaml: {where} genesis_block must be > 0")
                except (ValueError, TypeError):
                    errors.append(f"routes.yaml: {where} genesis_block must be an integer")
    indexer_ids = {str(r.get("id", "")).lower() for r in indexer}
    propagator_ids = {str(r.get("id", "")).lower() for r in propagator}
    if indexer_ids != propagator_ids:
        errors.append(f"routes.yaml: indexer and propagator route ids differ: {sorted(indexer_ids ^ propagator_ids)}")
    if len(indexer_ids) != len(indexer) or len(propagator_ids) != len(propagator):
        errors.append("routes.yaml: duplicate route ids")
    missing = expected_pairs - seen_pairs
    if missing:
        errors.append(f"routes.yaml: propagator routes missing for {sorted(missing)}")
    return errors


def check_artifacts(data: dict, env_dir: Path) -> list[str]:
    errors = []
    if "artifacts" not in data:
        artifacts_dir = env_dir / "artifacts"
        if artifacts_dir.is_dir() and any(artifacts_dir.rglob("*")):
            return ["artifacts/ exists on disk but config.yaml declares no artifacts"]
        return errors
    for name, artifact in data.get("artifacts", {}).items():
        path = env_dir / artifact["path"]
        if not path.is_file():
            errors.append(f"artifacts/{name}: {artifact['path']} does not exist")
            continue
        blob = path.read_bytes()
        if "sha256" in artifact:
            actual = hashlib.sha256(blob).hexdigest()
            if actual != artifact["sha256"]:
                errors.append(f"artifacts/{name}: sha256 mismatch (file {actual})")
        else:
            actual = keccak256(blob)
            if actual is None:
                print(f"  warn artifacts/{name}: keccak256 unavailable (pip install 'eth-hash[pycryptodome]')")
            elif "0x" + actual != artifact["keccak256"]:
                errors.append(f"artifacts/{name}: keccak256 mismatch (file 0x{actual})")
    artifacts_dir = env_dir / "artifacts"
    on_disk = sorted(str(p.relative_to(env_dir)) for p in artifacts_dir.rglob("*") if p.is_file()) if artifacts_dir.is_dir() else []
    declared = {a["path"] for a in data.get("artifacts", {}).values()}
    for extra in on_disk:
        if extra not in declared:
            errors.append(f"artifacts: {extra} is on disk but not declared in config.yaml")
    return errors


def main(argv: list[str]) -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    environments = yaml.safe_load(ENVIRONMENTS_PATH.read_text())

    configs = [Path(a).resolve() for a in argv] if argv else sorted(ROOT.glob(CONFIG_GLOB))
    if not configs:
        print(f"no configs matched {CONFIG_GLOB}", file=sys.stderr)
        return 1

    failed = 0
    for config in configs:
        rel = config.relative_to(ROOT) if config.is_relative_to(ROOT) else config
        data = yaml.safe_load(config.read_text())
        errors = [
            f"{'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}"
            for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        ]
        if not errors:
            errors += check_environment(data, config.parent.name, environments)
            errors += check_artifacts(data, config.parent)
            errors += check_routes(data, config.parent)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"PASS {rel}")

    print(f"\n{len(configs) - failed}/{len(configs)} configs valid")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
