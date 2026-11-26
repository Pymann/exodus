"""
Version pins (aiml spec/68 §7.5, F68-114 to F68-116).

A pin is an object of comparisons -- ``eq``, ``gt``, ``ge``, ``lt``, ``le`` --
all of which must hold, so ``{"ge": "1.0.2.7", "lt": "1.1"}`` is a range.
``eq`` stands alone, a bare string is no shorthand, an unknown key or a
range that admits nothing is an error.  Versions are dot-separated
non-negative integers, a leading ``v`` dropped, compared segment by segment
with a missing segment counting as 0.  `aiml build` reads the same keys with
the same rules: two readers of one format must not disagree (F68-119).
"""

from typing import List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

OPS = ("eq", "gt", "ge", "lt", "le")


def parse_version(text: str) -> Optional[Tuple[int, ...]]:
    """The segments of a version, None for anything F68-116 cannot read."""
    if text[:1] in ("v", "V"):
        text = text[1:]
    parts = text.split(".")
    if not text or any(not p.isdigit() or len(p) > 9 for p in parts):
        return None
    return tuple(int(p) for p in parts)


def compare_versions(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


class VersionRange(BaseModel):
    """``compiler.version`` / ``dependencies[].version`` (F68-115)."""

    model_config = ConfigDict(extra="forbid")

    eq: Optional[str] = None
    gt: Optional[str] = None
    ge: Optional[str] = None
    lt: Optional[str] = None
    le: Optional[str] = None

    @field_validator("eq", "gt", "ge", "lt", "le")
    @classmethod
    def _readable(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and parse_version(v) is None:
            raise ValueError(
                f"'{v}' is no version -- dot-separated numbers,"
                " e.g. 1.0.2.7 (aiml spec/68 F68-116)"
            )
        return v

    @model_validator(mode="after")
    def _shape(self) -> "VersionRange":
        ops = self.ops()
        if not ops:
            raise ValueError("a version pin is empty (aiml spec/68 F68-115)")
        if self.eq is not None and len(ops) > 1:
            raise ValueError("eq stands alone (aiml spec/68 F68-115)")
        lo: Optional[Tuple[Tuple[int, ...], bool]] = None
        hi: Optional[Tuple[Tuple[int, ...], bool]] = None
        for op, raw in ops:
            v = parse_version(raw)
            assert v is not None
            if op in ("gt", "ge"):
                c = 1 if lo is None else compare_versions(v, lo[0])
                if c > 0 or (c == 0 and op == "gt"):
                    lo = (v, op == "gt")
            elif op in ("lt", "le"):
                c = -1 if hi is None else compare_versions(v, hi[0])
                if c < 0 or (c == 0 and op == "lt"):
                    hi = (v, op == "lt")
        if lo is not None and hi is not None:
            c = compare_versions(lo[0], hi[0])
            if c > 0 or (c == 0 and (lo[1] or hi[1])):
                raise ValueError(
                    f"the version pin {self.show()} admits no version"
                    " (aiml spec/68 F68-115)"
                )
        return self

    def ops(self) -> List[Tuple[str, str]]:
        return [
            (op, getattr(self, op))
            for op in OPS
            if getattr(self, op) is not None
        ]

    def show(self) -> str:
        return "{" + ", ".join(f"{op} {v}" for op, v in self.ops()) + "}"

    def admits(self, version: str) -> bool:
        v = parse_version(version)
        if v is None:
            return False
        for op, raw in self.ops():
            w = parse_version(raw)
            assert w is not None
            c = compare_versions(v, w)
            if (
                (op == "eq" and c != 0)
                or (op == "gt" and c <= 0)
                or (op == "ge" and c < 0)
                or (op == "lt" and c >= 0)
                or (op == "le" and c > 0)
            ):
                return False
        return True
