"""Reproducible sample selection and the sample manifest.

Selection is done by *hash ranking*: every item gets the key
SHA-256("<seed>:<item_id>") and the n items with the lowest keys are chosen.
This is equivalent to a simple random sample, but unlike a language's random
number generator it is:

- reproducible forever (the result never depends on the Python version);
- re-performable by a reviewer or regulator with any SHA-256 tool;
- order-independent: shuffling or re-sorting the population file does not
  change which items are picked, only adding or removing items does.

The manifest records the seed, the population fingerprint and the selected
IDs, so the sample can be re-derived and checked later.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from .population import Population
from .stats import SampleSize

MANIFEST_VERSION = 1


def rank_key(seed: str, item_id: str) -> str:
    """Selection key for one item. Lower keys are selected first."""
    return hashlib.sha256(f"{seed}:{item_id}".encode("utf-8")).hexdigest()


def new_seed() -> str:
    """A fresh random seed (64 bits, hex) for when the auditor does not supply one."""
    return secrets.token_hex(8)


def select(ids: list[str], n: int, seed: str) -> list[str]:
    """Choose n IDs by hash ranking, returned in selection order."""
    if n < 0:
        raise ValueError("sample size cannot be negative")
    unique = sorted(set(ids))
    ranked = sorted(unique, key=lambda i: rank_key(seed, i))
    return ranked[:min(n, len(ranked))]


def allocate(strata_sizes: dict[str, int], n: int) -> dict[str, int]:
    """Split a sample of n across strata in proportion to their size
    (largest-remainder method). Every non-empty stratum gets at least one
    item when n allows, and no stratum gets more items than it holds."""
    strata = {k: v for k, v in strata_sizes.items() if v > 0}
    total = sum(strata.values())
    if total == 0:
        return {}
    n = min(n, total)
    alloc = {k: 0 for k in strata}
    if n >= len(strata):
        for k in strata:
            alloc[k] = 1
    remaining = n - sum(alloc.values())
    # Proportional share of what is left, capped by stratum capacity.
    shares = {k: remaining * strata[k] / total for k in strata}
    for k in strata:
        alloc[k] += min(math.floor(shares[k]), strata[k] - alloc[k])
    leftover = n - sum(alloc.values())
    order = sorted(strata, key=lambda k: (-(shares[k] - math.floor(shares[k])), -strata[k], k))
    while leftover > 0:
        progressed = False
        for k in order:
            if leftover and alloc[k] < strata[k]:
                alloc[k] += 1
                leftover -= 1
                progressed = True
        if not progressed:
            break
    return alloc


@dataclass
class Manifest:
    """Everything needed to re-perform and verify the sample."""
    control_id: str
    control_description: str
    seed: str
    drawn_on: str
    population_file: str
    population_sha256: str
    population_rows: int
    frame_size: int
    id_column: str
    sample_size: dict
    stratify_by: str | None = None
    allocation: dict[str, int] = field(default_factory=dict)
    selected: list[dict[str, str]] = field(default_factory=list)   # {"item_id", "stratum"}
    population_issues: list[dict] = field(default_factory=list)
    version: int = MANIFEST_VERSION

    @property
    def selected_ids(self) -> list[str]:
        return [s["item_id"] for s in self.selected]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("version") != MANIFEST_VERSION:
            raise ValueError(f"unsupported manifest version {data.get('version')}")
        return cls(**data)


def draw_sample(pop: Population, size: SampleSize, seed: str, control_id: str,
                control_description: str = "", stratify_by: str | None = None,
                drawn_on: date | None = None) -> Manifest:
    """Draw the sample from the population frame and build the manifest."""
    n = len(pop.frame) if size.test_all else min(size.n, len(pop.frame))
    selected: list[dict[str, str]] = []
    allocation: dict[str, int] = {}
    if stratify_by:
        col = next((f for f in pop.fieldnames if f.lower() == stratify_by.lower()), None)
        if col is None:
            raise ValueError(f"stratify column '{stratify_by}' not found")
        groups: dict[str, list[str]] = {}
        for row in pop.frame:
            groups.setdefault(row.get(col, "") or "(blank)", []).append(row[pop.id_column])
        allocation = allocate({k: len(v) for k, v in groups.items()}, n)
        for stratum in sorted(groups):
            for item_id in select(groups[stratum], allocation.get(stratum, 0), seed):
                selected.append({"item_id": item_id, "stratum": stratum})
    else:
        selected = [{"item_id": i, "stratum": ""} for i in select(pop.ids, n, seed)]

    return Manifest(
        control_id=control_id, control_description=control_description, seed=seed,
        drawn_on=(drawn_on or date.today()).isoformat(),
        population_file=Path(pop.path).name, population_sha256=pop.sha256,
        population_rows=len(pop.rows), frame_size=len(pop.frame), id_column=pop.id_column,
        sample_size={**size.to_dict(), "n": n}, stratify_by=stratify_by,
        allocation=allocation, selected=selected,
        population_issues=[i.to_dict() for i in pop.issues],
    )


def reperform(manifest: Manifest, pop: Population) -> list[str]:
    """Re-derive the selection from the manifest's seed and a population.
    Returns the list of differences (empty when the sample re-performs)."""
    problems: list[str] = []
    if pop.sha256 != manifest.population_sha256:
        problems.append("population file fingerprint differs from the one recorded at draw time")
    size = SampleSize(**manifest.sample_size)
    again = draw_sample(pop, size, manifest.seed, manifest.control_id,
                        stratify_by=manifest.stratify_by)
    if again.selected_ids != manifest.selected_ids:
        missing = set(manifest.selected_ids) - set(again.selected_ids)
        extra = set(again.selected_ids) - set(manifest.selected_ids)
        problems.append(f"re-derived selection differs ({len(missing)} recorded item(s) not "
                        f"re-selected, {len(extra)} new item(s) selected)")
    return problems
