from pathlib import Path
from typing import Any, ClassVar

C_TO_CPP_MAP: dict[str, str]

class Violation:
    _file_line_cache: ClassVar[dict[str, list[str]]]
    rule: str
    message: str
    file: Path | None
    line: int
    detector: str
    trigger: str

    def __init__(
        self,
        rule: str,
        message: str,
        file: Path | None,
        line: int = ...,
        detector: str = ...,
        trigger: str = ...,
    ) -> None: ...
    @staticmethod
    def _extract_trigger_from_message(message: str) -> str: ...
    @classmethod
    def _line_text(cls, file: Path | None, line: int) -> str: ...
    @classmethod
    def _extract_trigger_from_source(
        cls, file: Path | None, line: int
    ) -> str: ...
    def _derived_trigger(self) -> str: ...
    def __str__(self) -> str: ...

class MisraRule:
    name: str
    description: str
    query: str | None

    def __init__(
        self,
        name: str,
        description: str,
        query: str | None = ...,
    ) -> None: ...

def analyze_tree(
    tree: Any,
    file_path: Path,
    language: Any,
    source_code: bytes,
    project_config: Any = ...,
) -> list[Violation]: ...
