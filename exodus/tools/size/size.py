"""
exodus size — Binary size analysis for C/C++ projects.

Wraps system tools (size, nm, objdump) to provide per-file and per-symbol
memory breakdowns of compiled artifacts.

Usage:
    exodus size                     # Analyse default exodus.json project
    exodus size --all               # Analyse all exodus projects in cwd
    exodus size --top 20            # Show top 20 largest symbols
    exodus size --warn 64000        # Warn if any .o exceeds 64KB total
    exodus size --sections          # Show section breakdown per .o
    exodus size --diff <snapshot>   # Compare against saved snapshot
    exodus size --save <snapshot>   # Save current sizes as snapshot
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from exodus.core.logger import get_logger
from exodus.models.project import Project, ProjectConfig


logger = get_logger(__name__)


# ── Data models ──────────────────────────────────────────────────────────

@dataclass
class SectionInfo:
    """One section (text/data/bss) of a single .o or binary."""
    text: int = 0
    data: int = 0
    bss: int = 0

    @property
    def total(self) -> int:
        return self.text + self.data + self.bss


@dataclass
class SymbolInfo:
    """A single symbol from nm output."""
    name: str
    size: int
    kind: str  # T/t/D/d/B/b/R/r/...
    source_file: str = ""


@dataclass
class ObjectReport:
    """Size report for one object file."""
    path: Path
    sections: SectionInfo = field(default_factory=SectionInfo)
    symbols: List[SymbolInfo] = field(default_factory=list)


@dataclass
class ProjectReport:
    """Aggregated report for one exodus project."""
    name: str
    config_file: str
    objects: List[ObjectReport] = field(default_factory=list)
    binary: Optional[ObjectReport] = None

    @property
    def total_sections(self) -> SectionInfo:
        s = SectionInfo()
        for obj in self.objects:
            s.text += obj.sections.text
            s.data += obj.sections.data
            s.bss += obj.sections.bss
        return s


# ── System tool wrappers ────────────────────────────────────────────────

def _run_cmd(cmd: List[str]) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return r.stdout
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _which(tool: str) -> bool:
    """Check if a tool is available on PATH."""
    return _run_cmd(["which", tool]) is not None


def parse_size_output(output: str) -> SectionInfo:
    """Parse output of `size <file>` (Berkeley format).

    Expected format:
       text    data     bss     dec     hex filename
       1234     456      78    1768     6e8 file.o
    """
    lines = output.strip().splitlines()
    if len(lines) < 2:
        return SectionInfo()
    # Second line has the numbers
    parts = lines[1].split()
    if len(parts) < 3:
        return SectionInfo()
    try:
        return SectionInfo(
            text=int(parts[0]),
            data=int(parts[1]),
            bss=int(parts[2]),
        )
    except (ValueError, IndexError):
        return SectionInfo()


def parse_nm_output(output: str) -> List[SymbolInfo]:
    """Parse output of `nm --size-sort --print-size <file>`.

    Expected format:
        00000000 00000042 T function_name
        00000000 00000010 D global_var
    """
    symbols: List[SymbolInfo] = []
    for line in output.strip().splitlines():
        parts = line.split()
        # Format: addr size type name
        if len(parts) < 4:
            continue
        try:
            size = int(parts[1], 16)
            kind = parts[2]
            name = parts[3]
            symbols.append(SymbolInfo(name=name, size=size, kind=kind))
        except (ValueError, IndexError):
            continue
    return symbols


def get_sections(file_path: Path) -> SectionInfo:
    """Get section sizes for a file using `size`."""
    out = _run_cmd(["size", str(file_path)])
    if out is None:
        return SectionInfo()
    return parse_size_output(out)


def get_symbols(file_path: Path) -> List[SymbolInfo]:
    """Get symbols sorted by size using `nm`."""
    out = _run_cmd(["nm", "--size-sort", "--print-size", str(file_path)])
    if out is None:
        return []
    return parse_nm_output(out)


# ── Project discovery ───────────────────────────────────────────────────

def find_project_objects(
    project_root: Path, config: ProjectConfig,
) -> Tuple[List[Path], Optional[Path]]:
    """Find all .o files and the linked binary for a project config."""
    safe_name = config.name.replace("/", "_").replace("\\", "_")
    build_root = project_root / config.build_root / safe_name

    # Collect .o files
    obj_files: List[Path] = []
    if build_root.exists():
        obj_files = sorted(build_root.rglob("*.o"))

    # Find linked binary
    binary: Optional[Path] = None
    if config.output_type == "executable":
        bin_name = config.name
    elif config.output_type == "static_lib":
        bin_name = f"lib{config.name}.a"
    elif config.output_type == "shared_lib":
        bin_name = f"lib{config.name}.so"
    else:
        bin_name = config.name

    if config.artifact_in_cwd:
        candidate = project_root / bin_name
    else:
        candidate = build_root / bin_name

    if candidate.exists():
        binary = candidate

    return obj_files, binary


# ── Report generation ───────────────────────────────────────────────────

def build_report(
    project_root: Path, config: ProjectConfig,
) -> ProjectReport:
    """Build a full size report for one project."""
    obj_files, binary_path = find_project_objects(project_root, config)
    report = ProjectReport(
        name=config.name,
        config_file=str(config.build_root),
    )

    for obj_path in obj_files:
        obj_report = ObjectReport(
            path=obj_path,
            sections=get_sections(obj_path),
            symbols=get_symbols(obj_path),
        )
        report.objects.append(obj_report)

    if binary_path:
        report.binary = ObjectReport(
            path=binary_path,
            sections=get_sections(binary_path),
            symbols=get_symbols(binary_path),
        )

    return report


# ── Formatting helpers ──────────────────────────────────────────────────

def fmt_size(n: int) -> str:
    """Format byte count as human-readable."""
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


SYMBOL_KINDS = {
    "T": "text (func)",
    "t": "text (local)",
    "D": "data (init)",
    "d": "data (local)",
    "B": "bss (uninit)",
    "b": "bss (local)",
    "R": "rodata",
    "r": "rodata (local)",
    "W": "weak",
    "w": "weak (undef)",
    "V": "weak obj",
    "C": "common",
}


def print_report(
    report: ProjectReport,
    top_n: int = 10,
    show_sections: bool = False,
    warn_threshold: int = 0,
) -> int:
    """Print report to stdout. Returns number of warnings."""
    warnings = 0
    total = report.total_sections

    print(f"\n{'=' * 70}")
    print(f"  exodus size — {report.name}")
    print(f"{'=' * 70}")

    # ── Summary ──
    print(f"\n  Objects:  {len(report.objects)}")
    print(f"  Total:    {fmt_size(total.total)}"
          f"  (text: {fmt_size(total.text)}"
          f"  data: {fmt_size(total.data)}"
          f"  bss: {fmt_size(total.bss)})")

    if report.binary:
        bs = report.binary.sections
        print(f"  Binary:   {fmt_size(bs.total)}"
              f"  (text: {fmt_size(bs.text)}"
              f"  data: {fmt_size(bs.data)}"
              f"  bss: {fmt_size(bs.bss)})"
              f"  [{report.binary.path.name}]")

    # ── Per-object table ──
    if report.objects:
        print(f"\n  {'Object File':<45} {'text':>8} {'data':>8} {'bss':>8} {'total':>10}")
        print(f"  {'-' * 45} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 10}")

        sorted_objs = sorted(report.objects, key=lambda o: o.sections.total, reverse=True)
        for obj in sorted_objs:
            s = obj.sections
            name = obj.path.name
            if len(name) > 44:
                name = "..." + name[-41:]
            flag = ""
            if warn_threshold > 0 and s.total > warn_threshold:
                flag = " ⚠"
                warnings += 1
            print(f"  {name:<45} {s.text:>8} {s.data:>8} {s.bss:>8} {fmt_size(s.total):>10}{flag}")

    # ── Section breakdown ──
    if show_sections and report.objects:
        print(f"\n  Section Details:")
        for obj in sorted(report.objects, key=lambda o: o.sections.total, reverse=True)[:10]:
            print(f"\n    {obj.path.name}:")
            out = _run_cmd(["size", "-A", str(obj.path)])
            if out:
                for line in out.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith("."):
                        print(f"      {parts[0]:<25} {int(parts[1]):>10}")

    # ── Top symbols ──
    all_symbols: List[Tuple[str, SymbolInfo]] = []
    for obj in report.objects:
        for sym in obj.symbols:
            all_symbols.append((obj.path.name, sym))
    if report.binary:
        for sym in report.binary.symbols:
            all_symbols.append((report.binary.path.name, sym))

    all_symbols.sort(key=lambda x: x[1].size, reverse=True)

    if all_symbols and top_n > 0:
        print(f"\n  Top {min(top_n, len(all_symbols))} Symbols by Size:")
        print(f"  {'Size':>10}  {'Type':<14} {'Source':<30} {'Symbol'}")
        print(f"  {'-' * 10}  {'-' * 14} {'-' * 30} {'-' * 30}")
        for source, sym in all_symbols[:top_n]:
            kind_desc = SYMBOL_KINDS.get(sym.kind, sym.kind)
            sname = sym.name
            if len(sname) > 60:
                sname = sname[:57] + "..."
            print(f"  {fmt_size(sym.size):>10}  {kind_desc:<14} {source:<30} {sname}")

    # ── Warnings ──
    if warn_threshold > 0 and warnings > 0:
        print(f"\n  WARNING: {warnings} object(s) exceed threshold of {fmt_size(warn_threshold)}")

    print()
    return warnings


# ── Snapshot (diff) support ─────────────────────────────────────────────

def save_snapshot(report: ProjectReport, path: Path) -> None:
    """Save size data as JSON snapshot for later comparison."""
    data = {
        "name": report.name,
        "objects": {},
        "binary": None,
    }
    for obj in report.objects:
        s = obj.sections
        data["objects"][obj.path.name] = {
            "text": s.text, "data": s.data, "bss": s.bss,
        }
    if report.binary:
        bs = report.binary.sections
        data["binary"] = {
            "name": report.binary.path.name,
            "text": bs.text, "data": bs.data, "bss": bs.bss,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Snapshot saved: {path}")


def load_snapshot(path: Path) -> Optional[dict]:
    """Load a previously saved snapshot."""
    if not path.exists():
        print(f"  Error: Snapshot not found: {path}")
        return None
    with open(path) as f:
        return json.load(f)


def print_diff(report: ProjectReport, snapshot: dict) -> None:
    """Print diff between current report and saved snapshot."""
    print(f"\n  {'Object File':<40} {'old':>10} {'new':>10} {'diff':>10} {'%':>7}")
    print(f"  {'-' * 40} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 7}")

    old_objs = snapshot.get("objects", {})
    seen = set()

    for obj in sorted(report.objects, key=lambda o: o.sections.total, reverse=True):
        name = obj.path.name
        seen.add(name)
        new_total = obj.sections.total
        if name in old_objs:
            old_data = old_objs[name]
            old_total = old_data["text"] + old_data["data"] + old_data["bss"]
            diff = new_total - old_total
            pct = (diff / old_total * 100) if old_total > 0 else 0
            sign = "+" if diff > 0 else ""
            print(f"  {name:<40} {fmt_size(old_total):>10} {fmt_size(new_total):>10}"
                  f" {sign}{fmt_size(abs(diff)):>9} {sign}{pct:>6.1f}%")
        else:
            print(f"  {name:<40} {'(new)':>10} {fmt_size(new_total):>10}"
                  f" {'+' + fmt_size(new_total):>10} {'':>7}")

    # Objects that were removed
    for name, old_data in old_objs.items():
        if name not in seen:
            old_total = old_data["text"] + old_data["data"] + old_data["bss"]
            print(f"  {name:<40} {fmt_size(old_total):>10} {'(removed)':>10}"
                  f" {'-' + fmt_size(old_total):>10} {'-100.0%':>7}")

    # Binary diff
    if report.binary and snapshot.get("binary"):
        old_b = snapshot["binary"]
        old_bt = old_b["text"] + old_b["data"] + old_b["bss"]
        new_bt = report.binary.sections.total
        diff = new_bt - old_bt
        pct = (diff / old_bt * 100) if old_bt > 0 else 0
        sign = "+" if diff > 0 else ""
        print(f"\n  Binary: {fmt_size(old_bt)} -> {fmt_size(new_bt)}"
              f"  ({sign}{fmt_size(abs(diff))}, {sign}{pct:.1f}%)")


# ── Main Tool class ─────────────────────────────────────────────────────

class SizeTool:
    """exodus size — Binary size analysis."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    def _load_configs(self) -> List[Tuple[Path, ProjectConfig]]:
        """Load one or all project configs. Returns (project_root, config) pairs."""
        results: List[Tuple[Path, ProjectConfig]] = []
        cwd = Path.cwd()

        if getattr(self.args, "all", False):
            for config_name in Project.discover_config_names(cwd):
                try:
                    p = Project.load(cwd, config_name)
                    results.append((cwd, p.config))
                except Exception:
                    continue
        else:
            config_name = getattr(self.args, "config", "exodus.json")
            try:
                p = Project.load(cwd, config_name)
                results.append((cwd, p.config))
            except Exception as e:
                self.logger.error(f"Failed to load {config_name}: {e}")
        return results

    def run(self) -> int:
        """Execute the size analysis."""
        # Check that size and nm are available
        if not _which("size"):
            self.logger.error("'size' command not found. Install binutils.")
            return 1
        if not _which("nm"):
            self.logger.error("'nm' command not found. Install binutils.")
            return 1

        configs = self._load_configs()
        if not configs:
            self.logger.error("No project configs found.")
            return 1

        top_n = getattr(self.args, "top", 10)
        show_sections = getattr(self.args, "sections", False)
        warn_threshold = getattr(self.args, "warn", 0)
        save_path = getattr(self.args, "save", None)
        diff_path = getattr(self.args, "diff", None)

        total_warnings = 0

        for project_root, config in configs:
            report = build_report(project_root, config)

            if not report.objects and not report.binary:
                print(f"\n  {config.name}: No build artifacts found. Run 'exodus build' first.")
                continue

            # Diff mode
            if diff_path:
                snapshot = load_snapshot(Path(diff_path))
                if snapshot:
                    print(f"\n{'=' * 70}")
                    print(f"  exodus size diff — {report.name}")
                    print(f"  vs. {diff_path}")
                    print(f"{'=' * 70}")
                    print_diff(report, snapshot)
                    print()
                continue

            # Normal report
            w = print_report(
                report,
                top_n=top_n,
                show_sections=show_sections,
                warn_threshold=warn_threshold,
            )
            total_warnings += w

            # Save snapshot
            if save_path:
                save_snapshot(report, Path(save_path))

        return 1 if total_warnings > 0 else 0
