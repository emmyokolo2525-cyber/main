"""Structured fuzzing of the verifier-input boundary (Python layer).

Threat model
------------
The public-input frame and proof blob are fully attacker-controlled: they
arrive over HTTP from an untrusted client and are forwarded to a proving or
verifying backend. A malformed frame must therefore fail *deterministically*,
*cheaply*, and *silently* — never with an unexpected exception type, never with
unbounded work, and never by echoing attacker bytes into a log.

What this suite asserts
-----------------------
1. **Total.** For every mutant, :func:`classify` returns either ``None`` or a
   declared reject code. It never raises, never hangs, never returns anything
   outside the declared set.
2. **Deterministic.** A given seed always produces the same mutant sequence and
   the same verdict sequence. Failures are reproducible from the seed alone.
3. **Bounded.** Iteration counts and mutant sizes are fixed constants, so the
   CI budget for this file is a constant, not a function of luck.
4. **Silent.** No rejection signal ever contains attacker-supplied bytes.

The mutators, the PRNG, and the seed set are mirrored byte-for-byte by
``frontend/src/verifierInputs.fuzz.test.ts`` and
``contracts/contracts/harpocrates-registry/src/test_fuzz.rs`` so the three
layers explore the same space. Any input that ever produced a defect is
promoted into ``zk/vectors/fuzz_regressions_v1.json`` and replayed forever.

See docs/zk-fuzzing.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier_inputs import (
    FIELD_LEN,
    MAX_HEX_CHARS,
    MAX_PROOF_BYTES,
    PUBLIC_INPUTS_LEN,
    RejectCode,
    VerifierInputError,
    classify,
    decode_hex,
    parse_public_inputs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "zk" / "vectors" / "verifier_conformance_v1.json"
REGRESSIONS_PATH = REPO_ROOT / "zk" / "vectors" / "fuzz_regressions_v1.json"

CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
REGRESSIONS = json.loads(REGRESSIONS_PATH.read_text(encoding="utf-8"))

#: Deterministic seeds. Fixed, small, and shared with the other layers — the
#: budget for this file must not drift with CI mood.
SEEDS = (1, 7, 1337, 20260727)

#: Mutants generated per seed. Chosen so the whole file stays well inside a
#: second of CPU on CI while still covering every mutator many times over.
ITERATIONS_PER_SEED = 400

DECLARED_CODES = frozenset(code.value for code in RejectCode)

SCHEMAS = ("silent_witness/v1", "revocation_witness/v1")


# ── Deterministic PRNG (mirrored across all three layers) ───────────────────


class Lcg:
    """Numerical Recipes LCG. Chosen for exact reproducibility in Python,
    TypeScript, and Rust rather than for statistical quality."""

    __slots__ = ("state",)

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFF

    def next_u32(self) -> int:
        self.state = (self.state * 1664525 + 1013904223) & 0xFFFFFFFF
        return self.state

    def below(self, bound: int) -> int:
        return self.next_u32() % bound if bound > 0 else 0


# ── Structured mutators ─────────────────────────────────────────────────────
#
# Each mutator takes a well-formed frame and produces a neighbouring input.
# They are *structured* — aware of the 32-byte field grid — because purely
# random bytes almost never reach past the length check.

MUTATORS = (
    "truncate_tail",
    "extend_tail",
    "bit_flip",
    "byte_saturate",
    "field_zero",
    "field_saturate",
    "field_swap",
    "frame_duplicate",
    "frame_rotate",
    "field_modulus",
)

_MODULUS_BE = bytes.fromhex(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
)


def mutate(base: bytes, mutator: str, rng: Lcg) -> bytes:
    """Apply one structured mutation. Always returns a bounded byte string."""
    data = bytearray(base)

    if mutator == "truncate_tail":
        return bytes(data[: rng.below(len(data) + 1)])

    if mutator == "extend_tail":
        return bytes(data) + bytes(rng.below(256) for _ in range(1 + rng.below(64)))

    if mutator == "bit_flip":
        if not data:
            return bytes(data)
        index = rng.below(len(data))
        data[index] ^= 1 << rng.below(8)
        return bytes(data)

    if mutator == "byte_saturate":
        if not data:
            return bytes(data)
        index = rng.below(len(data))
        data[index] = 0xFF if rng.below(2) else 0x00
        return bytes(data)

    if mutator == "field_zero":
        index = rng.below(PUBLIC_INPUTS_LEN // FIELD_LEN)
        data[index * FIELD_LEN : (index + 1) * FIELD_LEN] = b"\x00" * FIELD_LEN
        return bytes(data)

    if mutator == "field_saturate":
        index = rng.below(PUBLIC_INPUTS_LEN // FIELD_LEN)
        data[index * FIELD_LEN : (index + 1) * FIELD_LEN] = b"\xff" * FIELD_LEN
        return bytes(data)

    if mutator == "field_modulus":
        index = rng.below(PUBLIC_INPUTS_LEN // FIELD_LEN)
        data[index * FIELD_LEN : (index + 1) * FIELD_LEN] = _MODULUS_BE
        return bytes(data)

    if mutator == "field_swap":
        count = PUBLIC_INPUTS_LEN // FIELD_LEN
        left, right = rng.below(count), rng.below(count)
        l0, r0 = left * FIELD_LEN, right * FIELD_LEN
        left_field = bytes(data[l0 : l0 + FIELD_LEN])
        right_field = bytes(data[r0 : r0 + FIELD_LEN])
        data[l0 : l0 + FIELD_LEN] = right_field
        data[r0 : r0 + FIELD_LEN] = left_field
        return bytes(data)

    if mutator == "frame_duplicate":
        return bytes(data) * 2

    if mutator == "frame_rotate":
        if not data:
            return bytes(data)
        offset = rng.below(len(data))
        return bytes(data[offset:] + data[:offset])

    raise AssertionError(f"unknown mutator: {mutator}")


def _positive_frames() -> dict[str, bytes]:
    """One canonical frame per schema, taken from the conformance corpus."""
    frames: dict[str, bytes] = {}
    for case in CORPUS["cases"]:
        if case["expect"]["accept"] and case["schema"] not in frames:
            frames[case["schema"]] = bytes.fromhex(case["public_inputs_hex"])
    return frames


POSITIVE_FRAMES = _positive_frames()
BASE_PROOF_HEX = "ab" * 64


# ── 1. Totality: no unexpected outcome, ever ────────────────────────────────


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("schema", SCHEMAS)
def test_mutants_always_produce_a_declared_verdict(schema: str, seed: int):
    base = POSITIVE_FRAMES[schema]
    rng = Lcg(seed)

    for iteration in range(ITERATIONS_PER_SEED):
        mutator = MUTATORS[rng.below(len(MUTATORS))]
        mutant = mutate(base, mutator, rng)

        verdict = classify(schema, mutant.hex(), BASE_PROOF_HEX)

        assert verdict is None or verdict in DECLARED_CODES, (
            f"seed={seed} schema={schema} iteration={iteration} mutator={mutator} "
            f"produced undeclared verdict {verdict!r}"
        )


@pytest.mark.parametrize("seed", SEEDS)
def test_mutated_proof_blobs_always_produce_a_declared_verdict(seed: int):
    schema = SCHEMAS[0]
    frame_hex = POSITIVE_FRAMES[schema].hex()
    rng = Lcg(seed)

    # Fewer iterations than the frame sweep: each mutant here materialises a
    # blob up to the codec ceiling, so the budget is bounded by bytes, not by
    # iteration count.
    for iteration in range(64):
        # Bounded by construction: never allocate past the codec's own ceiling.
        length = rng.below(MAX_PROOF_BYTES + 2)
        proof_hex = "cd" * length

        verdict = classify(schema, frame_hex, proof_hex)

        assert verdict is None or verdict in DECLARED_CODES, (
            f"seed={seed} iteration={iteration} proof_len={length} "
            f"produced undeclared verdict {verdict!r}"
        )


# ── 2. Determinism: the same seed replays exactly ───────────────────────────


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzz_run_is_reproducible_from_the_seed(seed: int):
    def run() -> list[tuple[str, str | None]]:
        rng = Lcg(seed)
        base = POSITIVE_FRAMES[SCHEMAS[0]]
        trace: list[tuple[str, str | None]] = []
        for _ in range(64):
            mutator = MUTATORS[rng.below(len(MUTATORS))]
            mutant = mutate(base, mutator, rng)
            trace.append((mutator, classify(SCHEMAS[0], mutant.hex(), BASE_PROOF_HEX)))
        return trace

    assert run() == run()


def test_distinct_seeds_explore_distinct_paths():
    """A guard against a mis-wired PRNG silently collapsing the search."""

    def trace(seed: int) -> list[str]:
        rng = Lcg(seed)
        return [MUTATORS[rng.below(len(MUTATORS))] for _ in range(64)]

    assert trace(SEEDS[0]) != trace(SEEDS[1])


# ── 3. Boundedness: hostile size never reaches an allocation ────────────────


def test_oversized_hex_is_rejected_without_decoding():
    """A caller must not be able to force a large allocation just to be told
    the value is too big."""
    with pytest.raises(VerifierInputError) as excinfo:
        decode_hex("a" * (MAX_HEX_CHARS + 2), field="proof")
    assert excinfo.value.code is RejectCode.PROOF_OVERSIZE


@pytest.mark.parametrize(
    "length",
    [0, 1, FIELD_LEN - 1, FIELD_LEN, PUBLIC_INPUTS_LEN - 1, PUBLIC_INPUTS_LEN + 1, 4096],
)
def test_arbitrary_frame_lengths_reject_on_length(length: int):
    if length == PUBLIC_INPUTS_LEN:
        pytest.skip("exact-length frames are covered by the conformance corpus")
    assert classify(SCHEMAS[0], "11" * length, BASE_PROOF_HEX) == "length"


# ── 4. Silence: rejections never carry attacker bytes ───────────────────────


@pytest.mark.parametrize("seed", SEEDS)
def test_rejection_signals_never_echo_mutant_bytes(seed: int):
    base = POSITIVE_FRAMES[SCHEMAS[0]]
    rng = Lcg(seed)

    for _ in range(128):
        mutator = MUTATORS[rng.below(len(MUTATORS))]
        mutant = mutate(base, mutator, rng)

        try:
            parse_public_inputs(SCHEMAS[0], mutant)
        except VerifierInputError as error:
            rendered = json.dumps(error.signal()) + str(error)
            assert set(error.signal()) <= {"codec", "reject_code", "field"}
            if len(mutant) >= 8:
                assert mutant[:8].hex() not in rendered
                assert mutant[-8:].hex() not in rendered


# ── 5. Minimized regression corpus ──────────────────────────────────────────


def test_regression_corpus_is_versioned():
    assert REGRESSIONS["format"] == "harpocrates.fuzz-regressions"
    assert REGRESSIONS["version"] == 1


@pytest.mark.parametrize(
    "entry", REGRESSIONS["entries"], ids=lambda entry: entry["id"]
)
def test_regression_entry_still_rejects_as_recorded(entry: dict):
    """Minimized inputs found by fuzzing are replayed forever.

    New findings are added here — minimized to the smallest input that still
    reproduces — rather than left to chance in a future random run.
    """
    actual = classify(entry["schema"], entry["public_inputs_hex"], entry["proof_hex"])
    assert actual == entry["expect_reject_code"], (
        f"{entry['id']}: expected {entry['expect_reject_code']!r}, got {actual!r} — "
        f"{entry['description']}"
    )
