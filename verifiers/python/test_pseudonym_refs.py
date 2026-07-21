import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name("src")))

from allowly_receipt_format import matches_ref


KEY = bytes(range(32))
RECORD_REF = (
    "hmac-v1:ecfc67ffb7bac447c05df24d1a25d75e"
    "be7e765320d0fb1b4d22be332341599e"
)
FULL_TUPLE_REF = (
    "hmac-v1:c5fa890e042ea330013bd07bcc47c331"
    "2136373493fe87a490907b0e93c5727a"
)


def test_matches_published_record_vector() -> None:
    assert matches_ref(KEY, "record", "MRN-48291", RECORD_REF)


def test_matches_published_full_tuple_vector() -> None:
    value = "\x1f".join(
        ("MRN-48291", "baseline_arm_1", "demographics", "demographics", "2")
    )
    assert matches_ref(KEY, "full_tuple", value, FULL_TUPLE_REF)


def test_mismatch_or_noncanonical_reference_returns_false() -> None:
    cases = [
        ("record", "MRN-48292", RECORD_REF),
        ("actor", "MRN-48291", RECORD_REF),
        ("record", "MRN-48291", RECORD_REF.upper()),
        ("record", "MRN-48291", RECORD_REF[:-1]),
        ("record", "MRN-48291", "sha256:" + RECORD_REF.removeprefix("hmac-v1:")),
    ]
    for field_name, value, ref in cases:
        assert not matches_ref(KEY, field_name, value, ref)


def test_value_is_not_unicode_normalized() -> None:
    composed = "Jos\u00e9"
    decomposed = "Jose\u0301"
    ref = "hmac-v1:76eca5c20d6d5d1c60f48bcd8b891f757e21a030e92f3cac90bc2462997f43ab"
    assert matches_ref(KEY, "actor", composed, ref)
    assert not matches_ref(KEY, "actor", decomposed, ref)


def test_rejects_weak_key_or_unknown_field() -> None:
    try:
        matches_ref(b"short", "record", "MRN-48291", RECORD_REF)
    except ValueError as exc:
        assert "128 bits" in str(exc)
    else:
        raise AssertionError("weak pseudonym key was accepted")

    try:
        matches_ref(KEY, "unknown", "MRN-48291", RECORD_REF)
    except ValueError as exc:
        assert "field name" in str(exc)
    else:
        raise AssertionError("unknown pseudonym field was accepted")


def main() -> None:
    test_matches_published_record_vector()
    test_matches_published_full_tuple_vector()
    test_mismatch_or_noncanonical_reference_returns_false()
    test_value_is_not_unicode_normalized()
    test_rejects_weak_key_or_unknown_field()
    print("hmac-v1 pseudonym reference vectors pass.")


if __name__ == "__main__":
    main()
