import json
from pathlib import Path

import pytest
from allowly_receipt_format import VerificationError, load_keys_from_json, verify_receipt

from assessment.verify import AssessmentError, verify_assessment

CASES = json.loads(Path(__file__).with_name("evidence-vectors.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_signed_assessment_vectors(case):
    arguments = dict(expected_workspace_id=case["workspace_id"], expected_project_id=case["project_id"], trusted_key_fingerprints=set(case["fingerprints"]))
    if case["valid"]:
        result = verify_assessment(case["signed_assessment"], case["keys"], case["source_snapshot"], case["policy_definition"], case["mapping_snapshot"], **arguments)
        assert result["mode"] == "observe" and result["intervention"] == "none"
        assert result["assessment_id"] == "asm_fictional"
    else:
        with pytest.raises(AssessmentError):
            verify_assessment(case["signed_assessment"], case["keys"], case["source_snapshot"], case["policy_definition"], case["mapping_snapshot"], **arguments)


def test_receipt_parser_keeps_rejecting_assessment_domain():
    case = CASES[0]
    with pytest.raises(VerificationError):
        verify_receipt(case["signed_assessment"], load_keys_from_json(case["keys"]), expected_workspace_id=case["workspace_id"], trusted_key_fingerprints=set(case["fingerprints"]))
