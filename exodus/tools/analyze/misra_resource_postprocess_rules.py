from pathlib import Path
from typing import Any, Callable

from exodus.tools.analyze.misra_rules import Violation


def apply_resource_postprocess_rules(
    *,
    file_path: Path,
    violations: list[Violation],
    alloc_resources: dict[str, dict[str, Any]],
    freed_heap: set[str],
    closed_files: set[str],
    file_opens: dict[str, list[dict[str, Any]]],
    is_write_mode: Callable[[str], bool],
) -> None:
    # Chapter 22 post-processing checks (heuristic).
    for var_hash, info in alloc_resources.items():
        kind = info.get("kind")
        line = info.get("line", 0)
        if kind == "heap":
            if var_hash not in freed_heap:
                trigger_text = f"resource[{var_hash}] kind=heap"
                violations.append(
                    Violation(
                        "Rule 22.1",
                        "All resources obtained dynamically by means of Standard Library functions shall be explicitly released.",
                        file_path,
                        line,
                        trigger=trigger_text,
                    )
                )
        elif kind == "file":
            if var_hash not in closed_files:
                trigger_text = f"resource[{var_hash}] kind=file"
                violations.append(
                    Violation(
                        "Rule 22.1",
                        "All resources obtained dynamically by means of Standard Library functions shall be explicitly released.",
                        file_path,
                        line,
                        trigger=trigger_text,
                    )
                )

    for fname, opens in file_opens.items():
        if len(opens) < 2:
            continue
        active = [o for o in opens if o.get("hash") not in closed_files]
        if len(active) < 2:
            continue
        has_read = any(not is_write_mode(o.get("mode", "")) for o in active)
        has_write = any(is_write_mode(o.get("mode", "")) for o in active)
        if has_read and has_write:
            line = active[0].get("line", 0)
            violations.append(
                Violation(
                    "Rule 22.3",
                    f"The same file '{fname}' shall not be open for read and write access at the same time on different streams.",
                    file_path,
                    line,
                    trigger=fname,
                )
            )
