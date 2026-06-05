"""
FolderLister v2 AI Resolver
============================
EXTRACT → NORMALIZE → RESOLVE → WRITE → REVIEW

Central resolver for all AI-extracted listing field candidates.
Keeps all field-level decision-making in one place — not scattered across
manage_listings.py merge paths, bulk-review helpers, and fallback branches.

Architecture
------------
1. Each extractor (image / voice / text / parser / profile / current) emits
   CandidateValue objects after normalization.
2. The resolver scores all candidates per field and picks a winner.
3. A ResolvedField is produced for every field that has at least one candidate.
4. A ListingResolutionResult bundles everything for the writer and the UI.

Non-negotiable rules
--------------------
- Image may never set price or quantity.
- Profile default/hint must not override explicit seller voice/text input.
- Profile locked is the only profile mode that can override seller input.
- All decisions must carry provenance (chosen_source, evidence, alternatives).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SOURCE_WEIGHTS: Dict[str, Dict[str, float]] = {
    "price": {
        "parser": 1.00, "voice": 0.93, "text": 0.89,
        "current": 0.72, "profile": 0.40, "image": 0.00,
    },
    "quantity": {
        "parser": 1.00, "voice": 0.92, "text": 0.88,
        "current": 0.70, "profile": 0.45, "image": 0.00,
    },
    "condition": {
        "voice": 0.90, "text": 0.86, "image": 0.78,
        "current": 0.68, "profile": 0.35,
    },
    "category": {
        "voice": 0.86, "text": 0.83, "image": 0.76,
        "profile": 0.74, "current": 0.65,
    },
    "specific_visual": {
        "image": 0.90, "voice": 0.82, "text": 0.78,
        "profile": 0.65, "current": 0.60,
    },
    "specific_nonvisual": {
        "parser": 0.97, "voice": 0.91, "text": 0.87,
        "profile": 0.79, "current": 0.68, "image": 0.35,
    },
    "title_identity": {
        "voice": 0.90, "text": 0.87, "image": 0.74,
        "profile": 0.66, "current": 0.60,
    },
}

PROFILE_MODE_WEIGHTS: Dict[str, float] = {
    "locked": 1.00,
    "default": 0.82,
    "hint": 0.62,
}

# Bonus when two sources agree semantically (use sorted tuple for lookup)
AGREEMENT_BONUS: Dict[Tuple[str, str], float] = {
    ("text", "voice"): 0.10,
    ("image", "voice"): 0.08,
    ("image", "text"): 0.06,
    ("profile", "voice"): 0.07,
    ("profile", "text"): 0.07,
    ("image", "profile"): 0.04,
}

# Penalty when two sources disagree
CONFLICT_PENALTY: Dict[Tuple[str, str], float] = {
    ("text", "voice"): 0.20,
    ("image", "voice"): 0.12,
    ("image", "text"): 0.12,
    ("profile", "voice"): 0.18,
    ("profile", "text"): 0.18,
    ("current", "voice"): 0.10,
    ("current", "text"): 0.10,
}

# Evidence quality by source_detail
EVIDENCE_QUALITY: Dict[str, float] = {
    "note_parser": 1.00,
    "voice_transcript": 0.95,
    "text_ai": 0.92,
    "image_ai": 0.90,
    "profile_locked": 1.00,
    "profile_default": 0.82,
    "profile_hint": 0.62,
    "existing_value": 0.75,
    "merged": 0.80,
}

# Aspect names whose facts are primarily determined by visual inspection
VISUAL_SPECIFIC_KEYS: FrozenSet[str] = frozenset({
    "color", "colour", "kleur", "color/colour",
    "material", "materiaal", "fabric", "fabric type", "stof",
    "style", "stijl", "design", "finish", "pattern", "patroon",
    "condition", "staat", "conditie",
    "type",
})

# Fields where image is absolutely forbidden as an evidence source
IMAGE_FORBIDDEN_FIELDS: FrozenSet[str] = frozenset({
    "price", "prijs", "quantity", "qty", "aantal",
})

# Confidence threshold below which a candidate is not auto-applied
AUTO_APPLY_THRESHOLD = 0.72
REVIEW_REQUIRED_THRESHOLD = 0.55


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CandidateValue:
    """
    A single extracted value candidate for a listing field.
    One field can have many candidates from different sources.
    The resolver picks the winner.
    """
    field_name: str
    value: str
    normalized_value: Any = None

    # Provenance
    source: str = ""          # parser | text | voice | image | profile | current | merged
    source_detail: str = ""   # note_parser | voice_transcript | text_ai | image_ai | profile_locked | ...
    field_kind: str = "other" # price | quantity | condition | category | specific_visual | specific_nonvisual | title_identity | other

    # Scoring inputs
    raw_confidence: float = 0.0       # 0–1 from extractor
    base_source_weight: float = 0.0   # from SOURCE_WEIGHTS
    evidence_quality: float = 0.0     # from EVIDENCE_QUALITY

    # Scoring modifiers (filled in by resolver)
    agreement_bonus: float = 0.0
    conflict_penalty: float = 0.0
    profile_mode: Optional[str] = None      # locked | default | hint | None
    profile_fit_score: float = 1.0

    # Final score (computed by resolver)
    final_confidence: float = 0.0

    # Validation
    allowed_match: Optional[bool] = None  # True = exact match, False = no match, None = no constraint
    explicitly_stated: bool = False        # seller explicitly stated this value
    visually_verified: bool = False        # directly visible in image
    resolver_eligible: bool = True         # False = rejected (e.g. image for price)

    # Reasoning
    evidence: List[str] = field(default_factory=list)
    conflicts_with: List[str] = field(default_factory=list)
    resolver_notes: List[str] = field(default_factory=list)
    apply_recommended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResolvedField:
    """
    The resolver's final decision for one listing field.
    Includes the winner, all alternatives, and a human-readable explanation.
    """
    field_name: str
    value: str
    normalized_value: Any = None
    field_kind: str = "other"

    final_confidence: float = 0.0
    chosen_source: str = ""
    chosen_source_detail: str = ""
    chosen_profile_mode: Optional[str] = None

    evidence: List[str] = field(default_factory=list)
    alternatives: List[Dict[str, Any]] = field(default_factory=list)

    apply_recommended: bool = False
    needs_review: bool = False
    resolver_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ListingResolutionResult:
    """
    Complete resolver output for one listing item.
    Consumed by the writer layer and the review UI.
    """
    resolved_fields: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    resolved_specifics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    missing_required: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    writer_input: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _norm(text: Any) -> str:
    """Whitespace-normalize and lowercase for comparison."""
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _values_agree(v1: str, v2: str) -> bool:
    """Semantic equality check — handles minor formatting differences."""
    if not v1 or not v2:
        return False
    n1, n2 = _norm(v1), _norm(v2)
    if n1 == n2:
        return True
    # Numeric normalization: "19.95", "19,95", "€19.95" → same
    def _num(s: str) -> Optional[float]:
        try:
            return float(re.sub(r"[^\d.]", "", s.replace(",", ".")))
        except Exception:
            return None
    num1, num2 = _num(n1), _num(n2)
    if num1 is not None and num2 is not None:
        return abs(num1 - num2) < 0.001
    return False


def _source_pair(s1: str, s2: str) -> Tuple[str, str]:
    """Canonical sorted tuple for AGREEMENT_BONUS / CONFLICT_PENALTY lookup."""
    return tuple(sorted([s1, s2]))  # type: ignore[return-value]


def _get_source_weight(field_kind: str, source: str) -> float:
    weights = SOURCE_WEIGHTS.get(field_kind) or SOURCE_WEIGHTS.get("specific_nonvisual", {})
    return float(weights.get(source, 0.0))


def _get_evidence_quality(source_detail: str) -> float:
    return EVIDENCE_QUALITY.get(source_detail, 0.75)


def _is_image_forbidden(field_kind: str, field_name: str) -> bool:
    """Price and quantity must never come from image analysis."""
    fn_l = _norm(field_name)
    return field_kind in ("price", "quantity") or fn_l in IMAGE_FORBIDDEN_FIELDS


def _infer_field_kind(field_name: str, source: str) -> str:
    fn_l = _norm(field_name)
    if fn_l in ("price", "prijs"):
        return "price"
    if fn_l in ("quantity", "qty", "aantal"):
        return "quantity"
    if fn_l in ("condition", "staat", "conditie"):
        return "condition"
    if fn_l in ("category", "categorie"):
        return "category"
    if fn_l in ("title", "title_suggestion", "titel"):
        return "title_identity"
    if source == "image" or fn_l in VISUAL_SPECIFIC_KEYS:
        return "specific_visual"
    return "specific_nonvisual"


# ─────────────────────────────────────────────────────────────────────────────
# NORMALIZERS — convert extractor output to CandidateValue lists
# ─────────────────────────────────────────────────────────────────────────────

def normalize_image_facts_to_candidates(
    facts: List[Dict[str, Any]],
    *,
    condition_candidates: Optional[List[Dict[str, Any]]] = None,
    title_hint: Optional[str] = None,
    title_confidence: int = 0,
) -> List[CandidateValue]:
    """
    Convert /web/ai/analyze-images output to CandidateValue list.
    Price and quantity candidates from images are silently dropped.
    """
    candidates: List[CandidateValue] = []

    for fact in (facts or []):
        key = str(fact.get("key") or "").strip()
        val = str(fact.get("value") or "").strip()
        acc_int = int(fact.get("accuracy") or 0)
        if not key or not val or acc_int < 40:
            continue

        fn_l = _norm(key)
        # Hard block: price and quantity forbidden from image
        if fn_l in IMAGE_FORBIDDEN_FIELDS:
            continue

        raw_conf = acc_int / 100.0
        fk = _infer_field_kind(key, "image")
        bsw = _get_source_weight(fk, "image")
        eq = _get_evidence_quality("image_ai")

        c = CandidateValue(
            field_name=key,
            value=val,
            normalized_value=val,
            source="image",
            source_detail="image_ai",
            field_kind=fk,
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            visually_verified=True,
            resolver_eligible=True,
            evidence=[f"image analysis: {key} = '{val}' ({acc_int}% visual certainty)"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Condition from image
    for cand in (condition_candidates or []):
        val = str(cand.get("value") or "").strip()
        acc_int = int(cand.get("accuracy") or 0)
        if not val or acc_int < 40:
            continue
        raw_conf = acc_int / 100.0
        bsw = _get_source_weight("condition", "image")
        eq = _get_evidence_quality("image_ai")
        c = CandidateValue(
            field_name="Condition",
            value=val,
            normalized_value=val,
            source="image",
            source_detail="image_ai",
            field_kind="condition",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            visually_verified=True,
            resolver_eligible=True,
            evidence=[f"image condition estimate: '{val}' ({acc_int}%)"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Title from image
    if title_hint and title_confidence >= 40:
        raw_conf = title_confidence / 100.0
        bsw = _get_source_weight("title_identity", "image")
        eq = _get_evidence_quality("image_ai")
        c = CandidateValue(
            field_name="title",
            value=title_hint,
            normalized_value=title_hint,
            source="image",
            source_detail="image_ai",
            field_kind="title_identity",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            visually_verified=True,
            resolver_eligible=True,
            evidence=[f"image title suggestion: '{title_hint}' ({title_confidence}%)"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    return candidates


def normalize_text_extract_to_candidates(
    result: Dict[str, Any],
    *,
    allowed_values: Optional[Dict[str, List[str]]] = None,
) -> List[CandidateValue]:
    """
    Convert /web/ai/analyze_description output to CandidateValue list.
    Price and quantity are included if explicitly stated.
    """
    candidates: List[CandidateValue] = []
    allowed_values = allowed_values or {}

    # Title
    title = str(result.get("title_suggestion") or "").strip()
    if title:
        bsw = _get_source_weight("title_identity", "text")
        eq = _get_evidence_quality("text_ai")
        raw_conf = float(result.get("title_confidence") or 0.7)
        c = CandidateValue(
            field_name="title",
            value=title,
            source="text",
            source_detail="text_ai",
            field_kind="title_identity",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            resolver_eligible=True,
            evidence=[f"text extraction title: '{title}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Condition
    cond = str(result.get("condition_suggestion") or "").strip()
    if cond:
        raw_conf = float(result.get("condition_confidence") or 0.72)
        bsw = _get_source_weight("condition", "text")
        eq = _get_evidence_quality("text_ai")
        c = CandidateValue(
            field_name="Condition",
            value=cond,
            source="text",
            source_detail="text_ai",
            field_kind="condition",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            resolver_eligible=True,
            evidence=[f"text: condition = '{cond}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Price — only if explicitly stated
    price_raw = result.get("price_suggestion")
    if price_raw is not None:
        price_str = str(price_raw).strip()
        raw_conf = float(result.get("price_confidence") or 0.85)
        bsw = _get_source_weight("price", "text")
        eq = _get_evidence_quality("text_ai")
        c = CandidateValue(
            field_name="price",
            value=price_str,
            normalized_value=_parse_numeric(price_str),
            source="text",
            source_detail="text_ai",
            field_kind="price",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"text: price = '{price_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Quantity — only if explicitly stated
    qty_raw = result.get("quantity_suggestion")
    if qty_raw is not None:
        qty_str = str(qty_raw).strip()
        raw_conf = float(result.get("quantity_confidence") or 0.85)
        bsw = _get_source_weight("quantity", "text")
        eq = _get_evidence_quality("text_ai")
        c = CandidateValue(
            field_name="quantity",
            value=qty_str,
            normalized_value=_parse_numeric(qty_str),
            source="text",
            source_detail="text_ai",
            field_kind="quantity",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"text: quantity = '{qty_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Specifics
    raw_specifics = result.get("specifics") or []
    if isinstance(raw_specifics, dict):
        raw_specifics = [{"name": k, "value": v, "confidence": result.get("confidence", {}).get(k, 0.7)} for k, v in raw_specifics.items() if v]
    for sp in raw_specifics:
        if not isinstance(sp, dict):
            continue
        name = str(sp.get("name") or "").strip()
        val = sp.get("value")
        if not name or not val:
            continue
        val_str = str(val).strip()
        raw_conf = float(sp.get("confidence") or 0.7)
        fn_l = _norm(name)
        fk = "specific_visual" if fn_l in VISUAL_SPECIFIC_KEYS else "specific_nonvisual"
        bsw = _get_source_weight(fk, "text")
        eq = _get_evidence_quality("text_ai")
        allowed = allowed_values.get(name, [])
        allowed_match = None
        if allowed:
            allowed_match = val_str in allowed
        c = CandidateValue(
            field_name=name,
            value=val_str,
            source="text",
            source_detail="text_ai",
            field_kind=fk,
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            allowed_match=allowed_match,
            resolver_eligible=True,
            evidence=[f"text: {name} = '{val_str}' ({int(raw_conf*100)}%)"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    return candidates


def normalize_voice_extract_to_candidates(
    result: Dict[str, Any],
    *,
    allowed_values: Optional[Dict[str, List[str]]] = None,
) -> List[CandidateValue]:
    """
    Convert /web/ai/describe-item output to CandidateValue list.
    Voice is the highest-trust explicit seller input for price/qty.
    """
    candidates: List[CandidateValue] = []
    allowed_values = allowed_values or {}

    # Title
    title = str(result.get("title_suggestion") or "").strip()
    if title:
        bsw = _get_source_weight("title_identity", "voice")
        eq = _get_evidence_quality("voice_transcript")
        raw_conf = float(result.get("title_confidence") or 0.78)
        c = CandidateValue(
            field_name="title",
            value=title,
            source="voice",
            source_detail="voice_transcript",
            field_kind="title_identity",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"voice title: '{title}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Condition
    cond = str(result.get("condition_suggestion") or "").strip()
    if cond:
        raw_conf = float(result.get("condition_confidence") or 0.82)
        bsw = _get_source_weight("condition", "voice")
        eq = _get_evidence_quality("voice_transcript")
        c = CandidateValue(
            field_name="Condition",
            value=cond,
            source="voice",
            source_detail="voice_transcript",
            field_kind="condition",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"voice: condition = '{cond}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Price
    price_raw = result.get("price_suggestion")
    if price_raw is not None:
        price_str = str(price_raw).strip()
        raw_conf = float(result.get("price_confidence") or 0.90)
        bsw = _get_source_weight("price", "voice")
        eq = _get_evidence_quality("voice_transcript")
        c = CandidateValue(
            field_name="price",
            value=price_str,
            normalized_value=_parse_numeric(price_str),
            source="voice",
            source_detail="voice_transcript",
            field_kind="price",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"voice: spoken price = '{price_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Quantity
    qty_raw = result.get("quantity_suggestion")
    if qty_raw is not None:
        qty_str = str(qty_raw).strip()
        raw_conf = float(result.get("quantity_confidence") or 0.88)
        bsw = _get_source_weight("quantity", "voice")
        eq = _get_evidence_quality("voice_transcript")
        c = CandidateValue(
            field_name="quantity",
            value=qty_str,
            normalized_value=_parse_numeric(qty_str),
            source="voice",
            source_detail="voice_transcript",
            field_kind="quantity",
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"voice: spoken quantity = '{qty_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    # Specifics
    raw_specifics = result.get("specifics") or []
    for sp in raw_specifics:
        if not isinstance(sp, dict):
            continue
        name = str(sp.get("name") or "").strip()
        val = sp.get("value")
        if not name or not val:
            continue
        val_str = str(val).strip()
        raw_conf = float(sp.get("confidence") or 0.78)
        fn_l = _norm(name)
        fk = "specific_visual" if fn_l in VISUAL_SPECIFIC_KEYS else "specific_nonvisual"
        bsw = _get_source_weight(fk, "voice")
        eq = _get_evidence_quality("voice_transcript")
        allowed = allowed_values.get(name, [])
        allowed_match = None
        if allowed:
            allowed_match = val_str in allowed
        c = CandidateValue(
            field_name=name,
            value=val_str,
            source="voice",
            source_detail="voice_transcript",
            field_kind=fk,
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            allowed_match=allowed_match,
            resolver_eligible=True,
            evidence=[f"voice: {name} = '{val_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)

    return candidates


def normalize_parser_candidates(
    parsed_fields: Dict[str, Any],
) -> List[CandidateValue]:
    """
    Convert deterministic parser output (price regex, qty pattern, etc.)
    to CandidateValue list. Parser has highest trust for price/qty.
    """
    candidates: List[CandidateValue] = []
    for field_name, val in parsed_fields.items():
        if not val:
            continue
        val_str = str(val).strip()
        fk = _infer_field_kind(field_name, "parser")
        bsw = _get_source_weight(fk, "parser")
        eq = _get_evidence_quality("note_parser")
        c = CandidateValue(
            field_name=field_name,
            value=val_str,
            normalized_value=_parse_numeric(val_str),
            source="parser",
            source_detail="note_parser",
            field_kind=fk,
            raw_confidence=1.0,
            base_source_weight=bsw,
            evidence_quality=eq,
            explicitly_stated=True,
            resolver_eligible=True,
            evidence=[f"deterministic parser: {field_name} = '{val_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq)
        candidates.append(c)
    return candidates


def normalize_profile_candidates(
    profile_specifics: Dict[str, Any],
    *,
    profile_mode: str = "default",
    profile_fit_score: float = 1.0,
) -> List[CandidateValue]:
    """
    Expose profile-defined values as candidates with a profile_mode.
    - locked: profile strongly wins unless seller manually overrides
    - default: strong prefill, loses to explicit voice/text
    - hint: soft signal, mainly for category/tie-breaking
    """
    if profile_mode not in PROFILE_MODE_WEIGHTS:
        profile_mode = "hint"
    mode_weight = PROFILE_MODE_WEIGHTS[profile_mode]
    eq = EVIDENCE_QUALITY.get(f"profile_{profile_mode}", 0.70)
    candidates: List[CandidateValue] = []

    for field_name, val in profile_specifics.items():
        if not val:
            continue
        val_str = str(val).strip()
        fk = _infer_field_kind(field_name, "profile")
        bsw = _get_source_weight(fk, "profile") * mode_weight
        raw_conf = profile_fit_score
        c = CandidateValue(
            field_name=field_name,
            value=val_str,
            source="profile",
            source_detail=f"profile_{profile_mode}",
            field_kind=fk,
            raw_confidence=raw_conf,
            base_source_weight=bsw,
            evidence_quality=eq,
            profile_mode=profile_mode,
            profile_fit_score=profile_fit_score,
            resolver_eligible=True,
            evidence=[f"profile ({profile_mode}): {field_name} = '{val_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * raw_conf)
        candidates.append(c)
    return candidates


def normalize_current_value_candidates(
    current_values: Dict[str, Any],
) -> List[CandidateValue]:
    """
    Represent existing item values as candidates.
    Lower trust than explicit seller input but higher than guesses.
    """
    candidates: List[CandidateValue] = []
    for field_name, val in current_values.items():
        if not val:
            continue
        val_str = str(val).strip()
        fk = _infer_field_kind(field_name, "current")
        bsw = _get_source_weight(fk, "current")
        eq = _get_evidence_quality("existing_value")
        c = CandidateValue(
            field_name=field_name,
            value=val_str,
            normalized_value=_parse_numeric(val_str),
            source="current",
            source_detail="existing_value",
            field_kind=fk,
            raw_confidence=0.80,
            base_source_weight=bsw,
            evidence_quality=eq,
            resolver_eligible=True,
            evidence=[f"existing value: {field_name} = '{val_str}'"],
        )
        c.final_confidence = min(1.0, bsw * eq * 0.80)
        candidates.append(c)
    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# RESOLVER CORE
# ─────────────────────────────────────────────────────────────────────────────

def _parse_numeric(val: Any) -> Optional[float]:
    try:
        s = re.sub(r"[^\d.,]", "", str(val or "")).replace(",", ".")
        return float(s) if s else None
    except Exception:
        return None


def _score_candidates(
    candidates: List[CandidateValue],
) -> List[CandidateValue]:
    """
    Apply agreement/conflict scoring across all candidates for the same field.
    Modifies candidates in-place (agreement_bonus, conflict_penalty, final_confidence).
    """
    eligible = [c for c in candidates if c.resolver_eligible]
    if len(eligible) < 2:
        return candidates

    # Compare each eligible pair
    for i, ci in enumerate(eligible):
        for cj in eligible[i + 1:]:
            pair = _source_pair(ci.source, cj.source)
            if _values_agree(ci.value, cj.value):
                bonus = AGREEMENT_BONUS.get(pair, 0.0)
                ci.agreement_bonus = max(ci.agreement_bonus, bonus)
                cj.agreement_bonus = max(cj.agreement_bonus, bonus)
                ci.resolver_notes.append(f"agrees with {cj.source}")
                cj.resolver_notes.append(f"agrees with {ci.source}")
            else:
                penalty = CONFLICT_PENALTY.get(pair, 0.0)
                ci.conflict_penalty = max(ci.conflict_penalty, penalty)
                cj.conflict_penalty = max(cj.conflict_penalty, penalty)
                ci.conflicts_with.append(f"{cj.source}:{cj.value}")
                cj.conflicts_with.append(f"{ci.source}:{ci.value}")

    # Recompute final_confidence with modifiers
    for c in eligible:
        profile_factor = PROFILE_MODE_WEIGHTS.get(c.profile_mode or "", 1.0) if c.profile_mode else 1.0
        raw = c.base_source_weight * c.evidence_quality * c.raw_confidence
        raw = raw * profile_factor * c.profile_fit_score
        raw = min(1.0, raw + c.agreement_bonus - c.conflict_penalty)
        c.final_confidence = max(0.0, raw)
        # Allowed-value bonus
        if c.allowed_match is True:
            c.final_confidence = min(1.0, c.final_confidence + 0.04)

    return candidates


def resolve_field(
    field_name: str,
    candidates: List[CandidateValue],
    *,
    required: bool = False,
    review_threshold: float = REVIEW_REQUIRED_THRESHOLD,
    auto_apply_threshold: float = AUTO_APPLY_THRESHOLD,
) -> Optional[ResolvedField]:
    """
    Resolve one field from a set of candidates.
    Returns None if no eligible candidate with a value exists.
    """
    if not candidates:
        return None

    # Filter eligible candidates
    eligible = [c for c in candidates if c.resolver_eligible and str(c.value or "").strip()]
    if not eligible:
        return None

    # Score (agreement/conflict modifiers)
    eligible = _score_candidates(eligible)

    # Sort: profile_locked wins outright over everything except explicit parser/voice
    # Otherwise sort by final_confidence desc
    def _sort_key(c: CandidateValue) -> Tuple:
        is_locked = c.profile_mode == "locked"
        is_explicit = c.source in ("parser", "voice") and c.explicitly_stated
        # locked profile loses to explicit seller parser/voice
        priority = 2 if is_locked and not is_explicit else (1 if is_explicit else 0)
        return (-priority, -c.final_confidence)

    eligible.sort(key=_sort_key)
    winner = eligible[0]
    alternatives = eligible[1:]

    needs_review = bool(
        winner.final_confidence < review_threshold
        or winner.conflicts_with
        or (required and not winner.value)
    )
    apply_recommended = (
        winner.final_confidence >= auto_apply_threshold
        and not needs_review
    )
    winner.apply_recommended = apply_recommended

    summary_parts = [
        f"Chosen: {winner.source} ({winner.source_detail}), "
        f"confidence={winner.final_confidence:.2f}",
    ]
    if winner.agreement_bonus > 0:
        summary_parts.append(f"agreement bonus +{winner.agreement_bonus:.2f}")
    if winner.conflict_penalty > 0:
        summary_parts.append(f"conflict penalty -{winner.conflict_penalty:.2f}")
    if winner.profile_mode:
        summary_parts.append(f"profile mode: {winner.profile_mode}")
    if alternatives:
        alt_summary = ", ".join(f"{a.source}:{a.value}" for a in alternatives[:3])
        summary_parts.append(f"alternatives: [{alt_summary}]")

    return ResolvedField(
        field_name=field_name,
        value=winner.value,
        normalized_value=winner.normalized_value,
        field_kind=winner.field_kind,
        final_confidence=winner.final_confidence,
        chosen_source=winner.source,
        chosen_source_detail=winner.source_detail,
        chosen_profile_mode=winner.profile_mode,
        evidence=list(winner.evidence),
        alternatives=[a.to_dict() for a in alternatives],
        apply_recommended=apply_recommended,
        needs_review=needs_review,
        resolver_summary=". ".join(summary_parts),
    )


def resolve_all_fields(
    all_candidates: List[CandidateValue],
    *,
    required_specifics: Optional[List[str]] = None,
    review_threshold: float = REVIEW_REQUIRED_THRESHOLD,
    auto_apply_threshold: float = AUTO_APPLY_THRESHOLD,
) -> ListingResolutionResult:
    """
    Resolve all fields from the full candidate pool.
    Separates core fields (title/condition/price/qty/category) from specifics.
    """
    required_specifics = required_specifics or []
    result = ListingResolutionResult()

    # Group candidates by field_name
    by_field: Dict[str, List[CandidateValue]] = {}
    for c in all_candidates:
        by_field.setdefault(c.field_name, []).append(c)

    # Core fields
    core_fields = {"title", "Condition", "condition", "price", "quantity", "category"}
    for fname, cands in by_field.items():
        rf = resolve_field(
            fname, cands,
            required=(fname in required_specifics),
            review_threshold=review_threshold,
            auto_apply_threshold=auto_apply_threshold,
        )
        if rf is None:
            continue
        fn_l = _norm(fname)
        if fn_l in ("title", "condition", "staat", "conditie", "price", "prijs", "quantity", "qty", "aantal", "category", "categorie"):
            result.resolved_fields[fname] = rf.to_dict()
        else:
            result.resolved_specifics[fname] = rf.to_dict()

    # Missing required specifics
    for req_name in required_specifics:
        if req_name not in result.resolved_specifics:
            result.missing_required.append(req_name)

    # Collect conflicts
    for fname, cands in by_field.items():
        for c in cands:
            if c.conflicts_with:
                msg = f"{fname}: {c.source} '{c.value}' conflicts with {'; '.join(c.conflicts_with[:2])}"
                if msg not in result.conflicts:
                    result.conflicts.append(msg)

    # Build writer_input for the writer layer
    result.writer_input = _build_writer_input(result)

    return result


def _build_writer_input(result: ListingResolutionResult) -> Dict[str, Any]:
    """Prepare a clean summary dict for the writer/description-generation layer."""
    def _get_val(d: Dict[str, Any]) -> str:
        return str(d.get("value") or "")

    wi: Dict[str, Any] = {}
    rf = result.resolved_fields
    if "title" in rf:
        wi["identity_basis"] = _get_val(rf["title"])
    if "Condition" in rf or "condition" in rf:
        wi["resolved_condition"] = _get_val(rf.get("Condition") or rf.get("condition") or {})
    if "price" in rf or "prijs" in rf:
        wi["resolved_price"] = _get_val(rf.get("price") or rf.get("prijs") or {})
    if "quantity" in rf or "qty" in rf:
        wi["resolved_quantity"] = _get_val(rf.get("quantity") or rf.get("qty") or {})
    if "category" in rf or "categorie" in rf:
        wi["resolved_category"] = _get_val(rf.get("category") or rf.get("categorie") or {})
    wi["resolved_specifics"] = {
        fname: _get_val(fd) for fname, fd in result.resolved_specifics.items() if _get_val(fd)
    }
    wi["missing_required"] = list(result.missing_required)
    wi["has_conflicts"] = bool(result.conflicts)
    return wi


# ─────────────────────────────────────────────────────────────────────────────
# COMPATIBILITY ADAPTER
# ─────────────────────────────────────────────────────────────────────────────

def build_legacy_compat_response(
    resolved: ListingResolutionResult,
    *,
    descriptions: Optional[Dict[str, str]] = None,
    transcript: str = "",
    category_candidates: Optional[List[Dict[str, Any]]] = None,
    search_terms: Optional[List[str]] = None,
    missing_required: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Wrap a ListingResolutionResult into the flat response shape the current
    manage_listings.py client expects.  Add the resolved_fields block so the
    UI can progressively start consuming provenance data.
    """
    rf = resolved.resolved_fields
    rs = resolved.resolved_specifics
    descriptions = descriptions or {}

    def _val(d: Optional[Dict[str, Any]]) -> str:
        return str((d or {}).get("value") or "")

    def _conf(d: Optional[Dict[str, Any]]) -> float:
        return float((d or {}).get("final_confidence") or 0.0)

    specifics_flat: Dict[str, str] = {}
    confidence_flat: Dict[str, float] = {}
    for fname, fd in rs.items():
        v = _val(fd)
        if v:
            specifics_flat[fname] = v
            confidence_flat[fname] = _conf(fd)

    return {
        # Legacy flat fields (existing client code reads these)
        "title_suggestion": _val(rf.get("title")),
        "title_confidence": _conf(rf.get("title")),
        "condition_suggestion": _val(rf.get("Condition") or rf.get("condition")),
        "condition_confidence": _conf(rf.get("Condition") or rf.get("condition")),
        "price_suggestion": _val(rf.get("price") or rf.get("prijs")) or None,
        "price_confidence": _conf(rf.get("price") or rf.get("prijs")),
        "quantity_suggestion": _val(rf.get("quantity") or rf.get("qty")) or None,
        "quantity_confidence": _conf(rf.get("quantity") or rf.get("qty")),
        "specifics": specifics_flat,
        "confidence": confidence_flat,
        "description_suggestion": descriptions.get("standard", ""),
        "factual_description_suggestion": descriptions.get("factual", ""),
        "seo_description_suggestion": descriptions.get("seo", ""),
        "missing_required": missing_required or resolved.missing_required,
        "category_candidates": category_candidates or [],
        "search_terms": search_terms or [],
        "transcript": transcript,
        "notes": resolved.conflicts,
        # v2 fields — progressively consumed by updated UI
        "resolved_fields": rf,
        "resolved_specifics": rs,
        "conflicts": resolved.conflicts,
        "writer_input": resolved.writer_input,
    }
