import json
import os
import sys
import faulthandler
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, TypedDict, cast

import clang.cindex

from exodus.models.project import ProjectConfig
from exodus.tools.analyze.libclang_config import resolve_libclang_path
from exodus.tools.analyze.misra_clang_rules import analyze_clang_ast


class WorkerCrossTUDatabase:
    def __init__(self) -> None:
        self.identifiers: Dict[str, Set[Tuple[str, int, str, str]]] = {}
        self.ext_objects: Dict[str, ExtRecord] = {}

    def _ensure_ext_record(self, name: str) -> "ExtRecord":
        if name not in self.ext_objects:
            self.ext_objects[name] = {
                "decls": set(),
                "defns": set(),
                "tu_users": set(),
                "signatures": [],
            }
        return self.ext_objects[name]

    def add(
        self, name: str, file_path: str, line: int, linkage: str, category: str
    ) -> None:
        if name not in self.identifiers:
            self.identifiers[name] = set()
        self.identifiers[name].add(
            (str(file_path), int(line), str(linkage), str(category))
        )

    def update_ext(
        self,
        name: str,
        decl_file: str | None,
        is_defn: bool,
        tu_path: str | None,
    ) -> None:
        record = self._ensure_ext_record(name)
        if decl_file:
            if is_defn:
                record["defns"].add(decl_file)
            else:
                record["decls"].add(decl_file)
        if tu_path:
            record["tu_users"].add(tu_path)

    def add_decl_signature(
        self,
        name: str,
        file_path: str,
        line: int,
        return_type: str,
        params: List[Tuple[str, str]],
    ) -> None:
        record = self._ensure_ext_record(name)
        record["signatures"].append(
            {
                "file": str(file_path),
                "line": int(line),
                "ret": str(return_type),
                "params": params,
            }
        )

    def to_json(self) -> Dict[str, Any]:
        identifiers = {
            name: [
                {
                    "file": f,
                    "line": line,
                    "linkage": linkage,
                    "category": category,
                }
                for (f, line, linkage, category) in sorted(entries)
            ]
            for name, entries in self.identifiers.items()
        }
        ext_objects: dict[str, dict[str, Any]] = {}
        for name, rec in self.ext_objects.items():
            ext_objects[name] = {
                "decls": sorted(list(rec["decls"])),
                "defns": sorted(list(rec["defns"])),
                "tu_users": sorted(list(rec["tu_users"])),
                "signatures": rec["signatures"],
            }
        return {"identifiers": identifiers, "ext_objects": ext_objects}


class SignatureRecord(TypedDict):
    file: str
    line: int
    ret: str
    params: List[Tuple[str, str]]


class ExtRecord(TypedDict):
    decls: Set[str]
    defns: Set[str]
    tu_users: Set[str]
    signatures: List[SignatureRecord]


def _config_from_payload(payload: Dict[str, object]) -> ProjectConfig:
    raw = payload.get("project_config", {}) or {}
    try:
        return ProjectConfig.model_validate(raw)
    except AttributeError:
        return ProjectConfig.parse_obj(raw)


def main() -> int:
    try:
        # Emit Python stack traces on fatal signals (e.g. SIGILL/SIGSEGV)
        # to make libclang worker crashes diagnosable in stderr/debug logs.
        faulthandler.enable(all_threads=True)
        payload = json.loads(sys.stdin.read() or "{}")
        source_file = Path(cast(str, payload["source_file"]))
        raw_clang_args = payload.get("clang_args", [])
        clang_args = (
            [str(arg) for arg in raw_clang_args]
            if isinstance(raw_clang_args, list)
            else []
        )
        config = _config_from_payload(payload)

        try:
            resolved_libclang = resolve_libclang_path(
                preferred_path=config.clang_library_file
            )
            if resolved_libclang is not None:
                clang.cindex.Config.set_library_file(str(resolved_libclang))
        except Exception:
            pass

        db = WorkerCrossTUDatabase()
        index = clang.cindex.Index.create()
        options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        tu = index.parse(str(source_file), args=clang_args, options=options)
        parse_only = os.environ.get("EXODUS_CLANG_PARSE_ONLY", "").strip() in {
            "1",
            "true",
            "yes",
        }
        if parse_only:
            violations = []
        else:
            violations = analyze_clang_ast(tu, source_file, db, config)
        out = {
            "violations": [
                {
                    "rule": v.rule,
                    "message": v.message,
                    "file": str(v.file) if v.file else "",
                    "line": int(v.line),
                    "detector": v.detector,
                    "trigger": getattr(v, "trigger", "")
                    or v._derived_trigger(),
                }
                for v in violations
            ]
        }
        out.update(db.to_json())
        sys.stdout.write(json.dumps(out))
        return 0
    except Exception as exc:
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
