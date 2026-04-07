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
from exodus.tools.analyze.misra_rules import Violation

CLANG_WORKER_CONTRACT_VERSION = 1


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


def _serialize_violations(violations: List[Violation]) -> List[Dict[str, Any]]:
    return [
        {
            "rule": v.rule,
            "message": v.message,
            "file": str(v.file) if v.file else "",
            "line": int(v.line),
            "detector": v.detector,
            "trigger": getattr(v, "trigger", "") or v._derived_trigger(),
        }
        for v in violations
    ]


def _emit_worker_status(
    *,
    stage: str,
    source_file: Path,
    mode: str,
    detail: str = "",
    extra: Dict[str, Any] | None = None,
) -> None:
    payload: Dict[str, Any] = {
        "stage": stage,
        "file": str(source_file),
        "mode": mode,
    }
    if detail:
        payload["detail"] = detail
    if extra:
        payload.update(extra)
    state_file = os.environ.get("EXODUS_CLANG_STATE_FILE", "").strip()
    if state_file:
        try:
            state_path = Path(state_file)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(payload, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass
    try:
        sys.stderr.write("[clang-worker] " + json.dumps(payload) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _scan_header_rule_3_1_1(
    header: Path, clang_args: List[str]
) -> List[Violation]:
    violations: List[Violation] = []
    idx = clang.cindex.Index.create()
    tu = idx.parse(
        str(header),
        args=clang_args,
        options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
    )

    header_resolved = header.resolve()
    for cursor in tu.cursor.walk_preorder():
        try:
            loc = cursor.location
            if not loc.file:
                continue
            if Path(loc.file.name).resolve() != header_resolved:
                continue
            parent = cursor.semantic_parent
            if not parent or parent.kind not in (
                clang.cindex.CursorKind.TRANSLATION_UNIT,
                clang.cindex.CursorKind.NAMESPACE,
            ):
                continue

            if (
                cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL
                and cursor.is_definition()
            ):
                token_text = {t.spelling for t in cursor.get_tokens()}
                if "inline" in token_text or "constexpr" in token_text:
                    continue
                if cursor.storage_class in (
                    clang.cindex.StorageClass.STATIC,
                    clang.cindex.StorageClass.EXTERN,
                ):
                    continue
                violations.append(
                    Violation(
                        "Rule 3-1-1",
                        "Header contains a non-inline function definition that may violate ODR when included in multiple translation units.",
                        header,
                        int(loc.line),
                        detector="header-clang-heuristic",
                        trigger=cursor.spelling or "",
                    )
                )
            elif (
                cursor.kind == clang.cindex.CursorKind.VAR_DECL
                and cursor.is_definition()
            ):
                token_text = {t.spelling for t in cursor.get_tokens()}
                if {"inline", "constexpr", "constinit"} & token_text:
                    continue
                if cursor.storage_class in (
                    clang.cindex.StorageClass.STATIC,
                    clang.cindex.StorageClass.EXTERN,
                ):
                    continue
                violations.append(
                    Violation(
                        "Rule 3-1-1",
                        "Header contains a namespace-scope object definition that may violate ODR when included in multiple translation units.",
                        header,
                        int(loc.line),
                        detector="header-clang-heuristic",
                        trigger=cursor.spelling or "",
                    )
                )
        except Exception:
            continue
    return violations


def main() -> int:
    try:
        # Emit Python stack traces on fatal signals (e.g. SIGILL/SIGSEGV)
        # to make libclang worker crashes diagnosable in stderr/debug logs.
        # Contract: worker returns JSON with a versioned envelope so the main
        # process can merge TU facts and violations without inspecting libclang.
        faulthandler.enable(all_threads=True)
        payload = json.loads(sys.stdin.read() or "{}")
        mode = str(payload.get("mode", "tu"))
        source_file = Path(cast(str, payload["source_file"]))
        _emit_worker_status(
            stage="worker-started",
            source_file=source_file,
            mode=mode,
        )
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
            _emit_worker_status(
                stage="libclang-configured",
                source_file=source_file,
                mode=mode,
                extra={"libclang_path": str(resolved_libclang or "")},
            )
        except Exception:
            pass

        if mode == "header_rule_3_1_1":
            _emit_worker_status(
                stage="header-scan",
                source_file=source_file,
                mode=mode,
            )
            violations = _scan_header_rule_3_1_1(source_file, clang_args)
            sys.stdout.write(
                json.dumps(
                    {
                        "contract_version": CLANG_WORKER_CONTRACT_VERSION,
                        "mode": mode,
                        "violations": _serialize_violations(violations),
                    }
                )
            )
            return 0

        db = WorkerCrossTUDatabase()
        index = clang.cindex.Index.create()
        options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        _emit_worker_status(
            stage="parse-tu",
            source_file=source_file,
            mode=mode,
        )
        tu = index.parse(str(source_file), args=clang_args, options=options)
        _emit_worker_status(
            stage="parsed-tu",
            source_file=source_file,
            mode=mode,
        )
        parse_only = os.environ.get("EXODUS_CLANG_PARSE_ONLY", "").strip() in {
            "1",
            "true",
            "yes",
        }
        if parse_only:
            violations = []
        else:
            _emit_worker_status(
                stage="analyze-ast",
                source_file=source_file,
                mode=mode,
            )
            violations = analyze_clang_ast(tu, source_file, db, config)
        out = {
            "contract_version": CLANG_WORKER_CONTRACT_VERSION,
            "mode": mode,
            "violations": _serialize_violations(violations),
        }
        out.update(db.to_json())
        _emit_worker_status(
            stage="worker-finished",
            source_file=source_file,
            mode=mode,
            extra={"violations": len(violations)},
        )
        sys.stdout.write(json.dumps(out))
        return 0
    except Exception as exc:
        try:
            _emit_worker_status(
                stage="worker-exception",
                source_file=source_file,
                mode=mode,
                detail=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
