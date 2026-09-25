"""Unit tests for fact tasks (goal §3): grading rules and truth derivation.

No gdb required — derive_truth is exercised through a canned driver.
"""

import pytest

from bench.framework.generators import FAMILY_MODULES, derive_truth_for
from bench.framework.generators.inspect import FAMILY as INSPECT_FAMILY
from bench.framework.schema import SchemaError
from bench.framework.verifiers import VerifyError, canonical_fact, grade_facts


# -- grading rules -----------------------------------------------------------

def test_ints_compare_by_value_across_formats():
    truth = {"idg": 1234, "uflag": 0x1F, "strv": -3}
    results = grade_facts(truth, {"idg": "1234", "uflag": "0x1f", "strv": "-3"})
    assert all(r.passed for r in results)
    assert len(results) == 3


def test_missing_field_fails():
    results = grade_facts({"a": 1, "b": 2}, {"a": 1})
    assert any(r.op == "fact_missing" and not r.passed for r in results)


def test_hallucinated_field_fails_even_when_truth_matches():
    results = grade_facts({"a": 1}, {"a": 1, "invented": 42})
    assert any(r.op == "fact_hallucinated" and not r.passed for r in results)


def test_wrong_value_fails():
    assert any(not r.passed for r in grade_facts({"signal": "SIGSEGV"},
                                                 {"signal": "SIGILL"}))


def test_non_dict_answer_is_total_failure():
    results = grade_facts({"a": 1}, "I set the breakpoint and everything is fine")
    assert len(results) == 1 and not results[0].passed
    assert not grade_facts({"a": 1}, None)[0].passed


def test_empty_truth_never_passes():
    assert not grade_facts({}, {"a": 1})[0].passed


def test_canonical_fact_parses_gdb_style_suffixes():
    assert canonical_fact("0x10") == canonical_fact(16) == canonical_fact("16")


# -- inspect family ----------------------------------------------------------

def test_inspect_generation_is_deterministic_and_valid():
    module = FAMILY_MODULES[INSPECT_FAMILY]
    for seed in (1, 2, 3, 4):
        a, b = module.generate(seed), module.generate(seed)
        assert a.to_json() == b.to_json()
        a.validate()
        assert a.kind == "fact"
        assert a.params["fact_fields"]
        for field in a.params["fact_fields"]:
            assert field in a.prompt  # the answer contract is explicit
        assert "answer" in a.prompt


def test_inspect_shapes_alternate_by_seed():
    module = FAMILY_MODULES[INSPECT_FAMILY]
    assert module.generate(1).params["shape"] == "crash_facts"
    assert module.generate(2).params["shape"] == "report_globals"


def test_inspect_rejects_unknown_kind_still_enforced():
    task = FAMILY_MODULES[INSPECT_FAMILY].generate(1)
    task.kind = "boolean"
    with pytest.raises(SchemaError):
        task.validate()


# -- truth derivation (canned driver) ----------------------------------------

class CannedDriver:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def call(self, tool, arguments=None):
        self.calls.append((tool, arguments))
        response = self.responses[tool]
        if callable(response):
            response = response(arguments or {})
        return response


def _report_driver():
    idg = (1234).to_bytes(4, "little").hex()
    uflag = (0xBEEF).to_bytes(4, "little").hex()
    strv = (7).to_bytes(2, "little").hex()  # stop value is acc & 0x7f: 0..127

    def mem(args):
        return {"hex": {"&idg": idg, "&uflag": uflag, "&strv": strv}[args["address"]]}

    return CannedDriver({
        "get_backtrace": {"frames": [{"function": "report"}, {"function": "work"}]},
        "read_registers": {"regs": {"rdi": "0x3e7"}},
        "read_memory": mem,
    })


@pytest.mark.asyncio
async def test_derive_truth_report_globals():
    task = FAMILY_MODULES[INSPECT_FAMILY].generate(2)  # report_globals
    driver = _report_driver()
    truth = await derive_truth_for(INSPECT_FAMILY)(driver, "s1", task)
    assert truth == {"token": 999, "idg": 1234, "uflag": 0xBEEF, "strv": 7}
    # a correct answer passes (any int format), a hallucination fails
    assert all(r.passed for r in grade_facts(truth, {"token": "0x3e7", "idg": "1234",
                                                     "uflag": 48879, "strv": "0x7"}))
    assert any(not r.passed
               for r in grade_facts(truth, dict(truth, invented="x")))


@pytest.mark.asyncio
async def test_derive_truth_requires_stopping_in_report():
    task = FAMILY_MODULES[INSPECT_FAMILY].generate(2)
    driver = CannedDriver({
        "get_backtrace": {"frames": [{"function": "main"}]},
        "read_registers": {"regs": {}},
        "read_memory": lambda args: {"hex": ""},
    })
    with pytest.raises(VerifyError):
        await derive_truth_for(INSPECT_FAMILY)(driver, "s1", task)


@pytest.mark.asyncio
async def test_derive_truth_crash_facts():
    task = FAMILY_MODULES[INSPECT_FAMILY].generate(1)  # crash_facts
    driver = CannedDriver({
        "get_stop_reason": {"stop_info": {"signal": "SIGSEGV", "fault_addr": "0x10"}},
        "get_backtrace": {"frames": [{"function": "deref"}, {"function": "trigger"}]},
    })
    truth = await derive_truth_for(INSPECT_FAMILY)(driver, "s1", task)
    assert truth == {"signal": "SIGSEGV", "fault_addr": 16,
                     "pc_function": "deref", "caller_function": "trigger"}
    assert all(r.passed for r in grade_facts(truth, truth))
    assert all(r.passed for r in grade_facts(
        truth, {"signal": "sigsegv", "fault_addr": "16",
                "pc_function": "deref", "caller_function": "trigger"}))


@pytest.mark.asyncio
async def test_derive_truth_crash_requires_frames():
    task = FAMILY_MODULES[INSPECT_FAMILY].generate(1)
    driver = CannedDriver({
        "get_stop_reason": {"stop_info": {"signal": "SIGSEGV", "fault_addr": "0x10"}},
        "get_backtrace": {"frames": [{"function": "deref"}]},  # caller missing
    })
    with pytest.raises(VerifyError):
        await derive_truth_for(INSPECT_FAMILY)(driver, "s1", task)


def test_state_families_have_no_derive_truth():
    assert derive_truth_for("crash") is None
    assert derive_truth_for("breakpoints") is None
