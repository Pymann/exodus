from pathlib import Path
from typing import Any

import clang.cindex

from exodus.models.project import ProjectConfig
from exodus.tools.analyze.misra_rules import Violation

def analyze_clang_ast(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    cross_tu_db: Any,
    config: ProjectConfig,
) -> list[Violation]: ...
