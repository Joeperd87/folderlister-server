"""
Unit tests for the FolderLister v2 AI Resolver.

Run with:  python -m pytest server/tests/test_ai_resolver.py -v

Tests cover the 12 acceptance scenarios from the design spec plus edge cases.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server.ai_resolver import (
    CandidateValue,
    ResolvedField,
    normalize_image_facts_to_candidates,
    normalize_text_extract_to_candidates,
    normalize_voice_extract_to_candidates,
    normalize_parser_candidates,
    normalize_profile_candidates,
    normalize_current_value_candidates,
    resolve_field,
    resolve_all_fields,
    IMAGE_FORBIDDEN_FIELDS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _voice_price(price: float) -> CandidateValue:
    """Quick voice-sourced price candidate."""
    cands = normalize_voice_extract_to_candidates(
        {"price_suggestion": price, "quantity_suggestion": None}
    )
    return next(c for c in cands if c.field_name == "price")


def _text_price(price: float) -> CandidateValue:
    cands = normalize_text_extract_to_candidates(
        {"price_suggestion": price}
    )
    return next(c for c in cands if c.field_name == "price")


def _parser_price(price: float) -> CandidateValue:
    cands = normalize_parser_candidates({"price": str(price)})
    return next(c for c in cands if c.field_name == "price")


def _image_fact(key: str, value: str, accuracy: int) -> list:
    return normalize_image_facts_to_candidates([{"key": key, "value": value, "accuracy": accuracy}])


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1 — Price from voice only
# ─────────────────────────────────────────────────────────────────────────────

def test_price_voice_only():
    """Voice says 24.95, no other price source. Should resolve cleanly."""
    c = _voice_price(24.95)
    rf = resolve_field("price", [c])
    assert rf is not None
    assert rf.value == "24.95"
    assert rf.chosen_source == "voice"
    assert not rf.needs_review
    assert rf.final_confidence > 0.6


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2 — Parser + voice agree on price
# ─────────────────────────────────────────────────────────────────────────────

def test_price_parser_voice_agree():
    """Parser and voice both find 19.95. Agreement bonus should boost confidence."""
    parser_c = _parser_price(19.95)
    voice_c = _voice_price(19.95)
    # Score together
    rf = resolve_field("price", [parser_c, voice_c])
    assert rf is not None
    assert rf.value == "19.95"
    # Parser wins (highest weight), but agreement bonus applies
    assert rf.chosen_source == "parser"
    assert rf.final_confidence > 0.85
    assert not rf.needs_review
    # At least one candidate should have agreement bonus
    all_scored = [parser_c, voice_c]
    assert any(c.agreement_bonus > 0 for c in all_scored)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3 — Price conflict between parser and voice
# ─────────────────────────────────────────────────────────────────────────────

def test_price_conflict_needs_review():
    """Parser says 19.95, voice says 24.95. Conflict → needs_review=True."""
    parser_c = _parser_price(19.95)
    voice_c = _voice_price(24.95)
    rf = resolve_field("price", [parser_c, voice_c])
    assert rf is not None
    assert rf.needs_review is True
    assert len(rf.alternatives) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4 — Image cannot set price
# ─────────────────────────────────────────────────────────────────────────────

def test_image_price_forbidden():
    """Image extractor emits a price-like fact. Must be rejected outright."""
    price_candidates = _image_fact("price", "19.95", 85)
    assert len(price_candidates) == 0, "Image price candidate should be silently dropped"

    # Also test via prijs (Dutch)
    prijs_candidates = _image_fact("prijs", "19.95", 90)
    assert len(prijs_candidates) == 0

    # And quantity
    qty_candidates = _image_fact("quantity", "3", 80)
    assert len(qty_candidates) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5 — Visual color: image wins over uncertain voice
# ─────────────────────────────────────────────────────────────────────────────

def test_visual_color_image_wins():
    """Image clearly says red (90%). Voice uncertain (50%). Image should win for color."""
    image_cands = _image_fact("color", "Red", 90)
    assert image_cands, "Image color candidate must be produced"
    image_c = image_cands[0]

    # Voice: uncertain
    voice_cands = normalize_voice_extract_to_candidates({
        "specifics": [{"name": "color", "value": "Orange-Red", "confidence": 0.50}]
    })
    voice_c = next((c for c in voice_cands if c.field_name == "color"), None)
    assert voice_c is not None

    rf = resolve_field("color", [image_c, voice_c])
    assert rf is not None
    assert rf.chosen_source == "image"
    assert "Red" in rf.value


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6 — Non-visual series: voice beats weak image
# ─────────────────────────────────────────────────────────────────────────────

def test_nonvisual_series_voice_beats_image():
    """Voice explicitly says 'Series 2'. Image weakly suggests 'Series 1'."""
    image_cands = normalize_image_facts_to_candidates([
        {"key": "Series", "value": "Series 1", "accuracy": 55}
    ])
    image_c = image_cands[0]
    image_c.field_kind = "specific_nonvisual"  # Not visually determined

    voice_cands = normalize_voice_extract_to_candidates({
        "specifics": [{"name": "Series", "value": "Series 2", "confidence": 0.91}]
    })
    voice_c = next((c for c in voice_cands if c.field_name == "Series"), None)
    assert voice_c is not None

    rf = resolve_field("Series", [image_c, voice_c])
    assert rf is not None
    assert rf.chosen_source == "voice"
    assert "2" in rf.value


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7 — Profile default agrees with seller
# ─────────────────────────────────────────────────────────────────────────────

def test_profile_default_agreement_bonus():
    """Profile says type=badge, voice says badge, image looks like badge.
    All agree → strong confidence with agreement bonus."""
    profile_cands = normalize_profile_candidates(
        {"type": "badge"}, profile_mode="default", profile_fit_score=0.9
    )
    voice_cands = normalize_voice_extract_to_candidates({
        "specifics": [{"name": "type", "value": "badge", "confidence": 0.88}]
    })
    image_cands = _image_fact("type", "badge", 82)

    all_cands = profile_cands + voice_cands + [c for c in image_cands if c.field_name == "type"]
    rf = resolve_field("type", all_cands)
    assert rf is not None
    # Any source pointing to badge
    assert "badge" in rf.value.lower()
    # At least one agreement bonus applied
    assert rf.final_confidence > 0.65


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 8 — Profile default conflicts with explicit voice
# ─────────────────────────────────────────────────────────────────────────────

def test_profile_default_loses_to_explicit_voice():
    """Profile default says 'badge', voice explicitly says 'pin'. Voice should win."""
    profile_cands = normalize_profile_candidates(
        {"type": "badge"}, profile_mode="default"
    )
    voice_cands = normalize_voice_extract_to_candidates({
        "specifics": [{"name": "type", "value": "pin", "confidence": 0.91}]
    })
    all_cands = profile_cands + voice_cands
    rf = resolve_field("type", all_cands)
    assert rf is not None
    assert rf.chosen_source == "voice"
    assert "pin" in rf.value.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 9 — Locked profile field wins / is visible
# ─────────────────────────────────────────────────────────────────────────────

def test_profile_locked_wins():
    """Profile locked Brand=LEGO. Text also says LEGO. Locked profile should win or support."""
    profile_cands = normalize_profile_candidates(
        {"Brand": "LEGO"}, profile_mode="locked"
    )
    text_cands = normalize_text_extract_to_candidates({
        "specifics": [{"name": "Brand", "value": "LEGO", "confidence": 0.85}]
    })
    all_cands = profile_cands + text_cands
    rf = resolve_field("Brand", all_cands)
    assert rf is not None
    assert rf.value == "LEGO"
    # Profile locked should be either winner or alternative with profile_mode=locked
    winner_profile_mode = rf.chosen_profile_mode
    alts_modes = [a.get("profile_mode") for a in rf.alternatives]
    assert winner_profile_mode == "locked" or "locked" in alts_modes


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 10 — Category consensus
# ─────────────────────────────────────────────────────────────────────────────

def test_category_consensus_high_confidence():
    """All sources point to same category. Confidence should be elevated."""
    voice_c = CandidateValue(
        field_name="category", value="badge collectibles",
        source="voice", source_detail="voice_transcript", field_kind="category",
        raw_confidence=0.86, base_source_weight=0.86, evidence_quality=0.95,
        resolver_eligible=True, explicitly_stated=True,
    )
    text_c = CandidateValue(
        field_name="category", value="badge collectibles",
        source="text", source_detail="text_ai", field_kind="category",
        raw_confidence=0.83, base_source_weight=0.83, evidence_quality=0.92,
        resolver_eligible=True,
    )
    image_c = CandidateValue(
        field_name="category", value="badge collectibles",
        source="image", source_detail="image_ai", field_kind="category",
        raw_confidence=0.76, base_source_weight=0.76, evidence_quality=0.90,
        resolver_eligible=True, visually_verified=True,
    )
    rf = resolve_field("category", [voice_c, text_c, image_c])
    assert rf is not None
    # All agree → agreement bonus → higher confidence
    assert rf.final_confidence > 0.80


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 11 — Category mismatch: voice beats image
# ─────────────────────────────────────────────────────────────────────────────

def test_category_mismatch_voice_beats_image():
    """Image says generic clothing. Voice says 'vintage football scarf'.
    Profile says 'sports memorabilia'. Voice + profile should outweigh generic image."""
    image_c = CandidateValue(
        field_name="category", value="clothing accessories",
        source="image", source_detail="image_ai", field_kind="category",
        raw_confidence=0.65, base_source_weight=0.76, evidence_quality=0.90,
        resolver_eligible=True, visually_verified=True,
    )
    voice_c = CandidateValue(
        field_name="category", value="vintage football scarf",
        source="voice", source_detail="voice_transcript", field_kind="category",
        raw_confidence=0.88, base_source_weight=0.86, evidence_quality=0.95,
        resolver_eligible=True, explicitly_stated=True,
    )
    profile_c = CandidateValue(
        field_name="category", value="sports memorabilia",
        source="profile", source_detail="profile_default", field_kind="category",
        raw_confidence=0.80, base_source_weight=0.74, evidence_quality=0.82,
        resolver_eligible=True, profile_mode="default",
    )
    rf = resolve_field("category", [image_c, voice_c, profile_c])
    assert rf is not None
    # Image generic guess should not win
    assert rf.chosen_source != "image"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 12 — Missing required specifics
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_required_specifics():
    """Required fields that stay unresolved appear in missing_required."""
    voice_cands = normalize_voice_extract_to_candidates({
        "specifics": [{"name": "Brand", "value": "Adidas", "confidence": 0.90}]
    })
    result = resolve_all_fields(
        voice_cands,
        required_specifics=["Brand", "Material", "Color"],
    )
    # Brand is resolved
    assert "Brand" in result.resolved_specifics
    # Material and Color are missing
    assert "Material" in result.missing_required
    assert "Color" in result.missing_required


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_candidates_returns_none():
    rf = resolve_field("price", [])
    assert rf is None


def test_image_quantity_forbidden():
    """Quantity from image must be silently dropped."""
    cands = _image_fact("aantal", "5", 80)  # Dutch for quantity
    assert len(cands) == 0

    cands2 = _image_fact("qty", "3", 90)
    assert len(cands2) == 0


def test_profile_hint_cannot_alone_force_field():
    """Profile hint should produce a low-confidence candidate — not auto-applied alone."""
    profile_cands = normalize_profile_candidates(
        {"Type": "badge"}, profile_mode="hint", profile_fit_score=0.7
    )
    rf = resolve_field("Type", profile_cands)
    assert rf is not None
    # Should be low confidence — not auto-applied
    assert rf.final_confidence < 0.75


def test_values_agree_numeric_variants():
    """19.95 and €19,95 should be treated as equal."""
    from server.ai_resolver import _values_agree
    assert _values_agree("19.95", "19,95") is True
    assert _values_agree("€19.95", "19.95") is True
    assert _values_agree("19.95", "24.95") is False


def test_resolve_all_fields_writer_input():
    """resolve_all_fields must build a valid writer_input block."""
    voice_result = {
        "price_suggestion": 24.95,
        "condition_suggestion": "Used",
        "specifics": [{"name": "Brand", "value": "Adidas", "confidence": 0.88}],
    }
    cands = normalize_voice_extract_to_candidates(voice_result)
    result = resolve_all_fields(cands)
    wi = result.writer_input
    assert "resolved_price" in wi or "resolved_condition" in wi
    assert "resolved_specifics" in wi


def test_image_color_low_accuracy_excluded():
    """Image facts below 40% accuracy should not produce candidates."""
    cands = _image_fact("color", "Blue", 35)
    assert len(cands) == 0


def test_parser_beats_everything_for_price():
    """Parser should be the top-ranked source for price when all agree."""
    parser_c = _parser_price(9.99)
    voice_c = _voice_price(9.99)
    text_c = _text_price(9.99)
    rf = resolve_field("price", [parser_c, voice_c, text_c])
    assert rf is not None
    assert rf.chosen_source == "parser"
