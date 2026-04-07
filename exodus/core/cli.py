"""
Main CLI module for Exodus.
"""

import sys
import argparse
from typing import Any
from exodus.tools.build.build import BuildTool
from exodus.tools.clean.clean import CleanTool
from exodus.tools.init.init import InitTool, get_available_templates
from exodus.tools.analyze.analyze import AnalyzeTool
from exodus.tools.analyze.misra_profiles import profile_choices
from exodus.tools.deps.deps import DepsTool
from exodus.tools.extract.extract import ExtractTool
from exodus.tools.pkg.package_manager import PackageManager
from exodus.tools.sbom.sbom import SbomTool
from exodus.tools.aiml_diagram import AimlDiagramTool
from exodus.core.logger import configure_logging


def main() -> None:
    """Entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Exodus: A universal build tool for C/C++ projects."
    )
    # Arguments
    __version__ = "0.1.0"
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands"
    )

    # Command: build
    build_parser = subparsers.add_parser("build", help="Build the project")
    build_parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=4,
        help="Number of parallel jobs (default: 4)",
    )
    build_parser.add_argument(
        "--clean", action="store_true", help="Clean before building"
    )
    build_parser.add_argument(
        "--config",
        default="exodus.json",
        metavar="FILE",
        help="Config file to use (default: exodus.json)",
    )
    build_parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Build all JSON files in the current directory that declare "
            "the Exodus project schema"
        ),
    )

    # Command: clean
    clean_parser = subparsers.add_parser("clean", help="Clean build artifacts")
    clean_parser.add_argument(
        "--all",
        action="store_true",
        help="Remove the entire build_root directory (e.g. out/).",
    )
    clean_parser.add_argument(
        "--config",
        default="exodus.json",
        metavar="FILE",
        help="Config file to use (default: exodus.json)",
    )

    # Command: init
    # from ..tools.init import get_available_templates

    available_templates = get_available_templates()

    init_parser = subparsers.add_parser(
        "init", help="Initialize a new project"
    )
    init_parser.add_argument(
        "template",
        nargs="?",
        default="cpp-simple",
        choices=available_templates if available_templates else None,
        help=(
            "Project template to use (choices: "
            f"{', '.join(available_templates)})"
        ),
    )
    init_parser.add_argument(
        "project",
        nargs="?",
        default=".",
        help="Target directory/project name for the new project",
    )

    # Command: analyze
    analyze_parser = subparsers.add_parser(
        "analyze", help="Run static analysis"
    )
    analyze_parser.add_argument(
        "tool",
        nargs="?",
        default="cppcheck",
        help="Analysis tool to run (default: cppcheck)",
    )
    analyze_parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=4,
        help="Number of parallel jobs for analysis (default: 4)",
    )
    analyze_parser.add_argument(
        "--misra-profile",
        default=None,
        choices=profile_choices(),
        help=(
            "MISRA profile for rule mapping and reporting "
            f"(overrides exodus.json; choices: {', '.join(profile_choices())})"
        ),
    )
    analyze_parser.add_argument(
        "--per-rule-output",
        action="store_true",
        help=(
            "Write grouped analysis output into out/analyze/<project>/ "
            "with one file per rule."
        ),
    )
    analyze_parser.add_argument(
        "--per-file-output",
        action="store_true",
        help=(
            "Write grouped analysis output into out/analyze/<project>/ "
            "with one .aal file per analyzed source file."
        ),
    )
    analyze_parser.add_argument(
        "--no-clang",
        action="store_true",
        help="Disable clang-based analysis and run tree-sitter-only (stability fallback).",
    )
    analyze_parser.add_argument(
        "--debug-clang",
        action="store_true",
        help="Write per-file clang invocation diagnostics to out/analyze/<project>/clang_debug.jsonl.",
    )
    analyze_parser.add_argument(
        "--single-rules",
        nargs="+",
        default=None,
        help=(
            "Only report the given MISRA rules (space or comma separated), "
            "e.g. --single-rules 8.4 17.3 or --single-rules 8.4,17.3"
        ),
    )
    analyze_parser.add_argument(
        "--skip-heuristic",
        nargs="+",
        default=None,
        metavar="NAME",
        help=(
            "Skip selected analysis pipelines. Supported names: "
            "tree-sitter, clang, regex, header-scan, cross-tu, project-config. "
            "Note: skipping clang also disables cross-tu automatically. "
            "Aliases: treesitter, ts, crosstu, config."
        ),
    )

    # Command: deps
    deps_parser = subparsers.add_parser("deps", help="Manage dependencies")
    deps_parser.add_argument(
        "action",
        choices=["install", "update", "list"],
        help="Action to perform",
    )

    # Command: extract
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract configuration from external project formats",
    )
    extract_parser.add_argument(
        "spec",
        nargs="*",
        help="Optional key=value args (e.g. type=cmake)",
    )
    extract_parser.add_argument(
        "--type",
        default="cmake",
        choices=["cmake"],
        help="Extractor type (default: cmake)",
    )
    extract_parser.add_argument(
        "--cmake-file",
        default="CMakeLists.txt",
        help="Path to CMakeLists.txt (default: CMakeLists.txt)",
    )

    # Command: sbom
    sbom_parser = subparsers.add_parser(
        "sbom", help="Generate a manifest SBOM from the project config"
    )
    sbom_parser.add_argument(
        "action",
        nargs="?",
        choices=["manifest", "resolve"],
        default="manifest",
        help="SBOM mode to generate (default: manifest)",
    )
    sbom_parser.add_argument(
        "--config",
        default="exodus.json",
        metavar="FILE",
        help="Config file to use (default: exodus.json)",
    )
    sbom_parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Generate SBOMs for all JSON files in the current directory "
            "that declare the Exodus project schema"
        ),
    )

    aiml_diagram_parser = subparsers.add_parser(
        "aiml-diagram",
        help="Generate Mermaid or PlantUML diagrams from AIML projects",
    )
    aiml_diagram_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project root to scan (default: current directory)",
    )
    aiml_diagram_parser.add_argument(
        "--config",
        default="exodus.json",
        metavar="FILE",
        help="Config file to use for AIML source discovery (default: exodus.json)",
    )
    aiml_diagram_parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Use all JSON files in the target directory that declare "
            "the Exodus project schema"
        ),
    )
    aiml_diagram_parser.add_argument(
        "--entry",
        action="append",
        default=[],
        help="Extra AIML entry file to include (can be passed multiple times)",
    )
    aiml_diagram_parser.add_argument(
        "--format",
        choices=["mermaid", "plantuml"],
        default="mermaid",
        help="Diagram output format (default: mermaid)",
    )
    aiml_diagram_parser.add_argument(
        "--diagram",
        choices=["state", "usecase", "both"],
        default="both",
        help="Diagram type to render (default: both)",
    )
    aiml_diagram_parser.add_argument(
        "--output",
        default=None,
        help="Optional output file path; stdout is used when omitted",
    )

    # Command: pkg
    pkg_parser = subparsers.add_parser(
        "pkg", help="Manage package/dependency entries in exodus.json"
    )
    pkg_subparsers = pkg_parser.add_subparsers(
        dest="action", required=True, help="Package actions"
    )

    pkg_list = pkg_subparsers.add_parser(
        "list", help="List configured packages"
    )
    pkg_list.add_argument(
        "--json",
        action="store_true",
        help="Print package list as JSON",
    )
    pkg_list.add_argument(
        "--type",
        choices=["all", "apt", "conan"],
        default="all",
        help="Filter listed package type (default: all)",
    )

    pkg_add = pkg_subparsers.add_parser("add", help="Add a package")
    pkg_add.add_argument("name", help="APT package name")
    pkg_add.add_argument(
        "--arch",
        required=True,
        help="Package architecture (e.g. amd64, i386)",
    )
    pkg_add.add_argument(
        "--version",
        required=True,
        help="Exact package version",
    )

    pkg_remove = pkg_subparsers.add_parser("remove", help="Remove a package")
    pkg_remove.add_argument("name", help="APT package name")
    pkg_remove.add_argument(
        "--arch",
        default=None,
        help="Optional architecture filter",
    )
    pkg_remove.add_argument(
        "--version",
        default=None,
        help="Optional version filter",
    )

    pkg_install = pkg_subparsers.add_parser(
        "install",
        help="Download/install configured apt packages into EXODUS_CACHE",
    )
    pkg_install.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Optional package name filter",
    )
    pkg_install.add_argument(
        "--arch",
        default=None,
        help="Optional architecture filter",
    )
    pkg_install.add_argument(
        "--version",
        default=None,
        help="Optional version filter",
    )
    pkg_install.add_argument(
        "--force",
        action="store_true",
        help="Force re-download and re-extract even when cache already exists",
    )
    pkg_install.add_argument(
        "--all",
        action="store_true",
        help=(
            "Install packages for all JSON files in the current directory "
            "that declare the Exodus project schema"
        ),
    )

    pkg_install_apt = pkg_subparsers.add_parser(
        "install-apt",
        help=(
            "Download and extract a single apt package into EXODUS_CACHE "
            "without modifying exodus.json"
        ),
    )
    pkg_install_apt.add_argument("name", help="APT package name")
    pkg_install_apt.add_argument(
        "--arch",
        required=True,
        help="Package architecture (e.g. amd64, i386)",
    )
    pkg_install_apt.add_argument(
        "--version",
        default=None,
        help=(
            "Exact package version. If omitted, highest available version is used."
        ),
    )
    pkg_install_apt.add_argument(
        "--force",
        action="store_true",
        help="Force re-download and re-extract even when cache already exists",
    )

    pkg_add_conan = pkg_subparsers.add_parser(
        "add-conan", help="Add a Conan package"
    )
    pkg_add_conan.add_argument("name", help="Conan package name")
    pkg_add_conan.add_argument(
        "--arch",
        required=True,
        help="Conan arch setting (e.g. x86_64, armv8)",
    )
    pkg_add_conan.add_argument(
        "--version",
        required=True,
        help="Conan package version",
    )
    pkg_add_conan.add_argument(
        "--user", default=None, help="Optional Conan user"
    )
    pkg_add_conan.add_argument(
        "--channel", default=None, help="Optional Conan channel"
    )
    pkg_add_conan.add_argument(
        "--profile", default=None, help="Optional Conan host profile"
    )
    pkg_add_conan.add_argument(
        "--build-profile", default=None, help="Optional Conan build profile"
    )
    pkg_add_conan.add_argument(
        "--remote", default=None, help="Optional Conan remote"
    )

    pkg_remove_conan = pkg_subparsers.add_parser(
        "remove-conan", help="Remove a Conan package"
    )
    pkg_remove_conan.add_argument("name", help="Conan package name")
    pkg_remove_conan.add_argument(
        "--arch",
        default=None,
        help="Optional architecture filter",
    )
    pkg_remove_conan.add_argument(
        "--version",
        default=None,
        help="Optional version filter",
    )

    pkg_install_conan_cfg = pkg_subparsers.add_parser(
        "install-conan-configured",
        help="Install Conan packages configured in exodus.json",
    )
    pkg_install_conan_cfg.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Optional package name filter",
    )
    pkg_install_conan_cfg.add_argument(
        "--arch",
        default=None,
        help="Optional architecture filter",
    )
    pkg_install_conan_cfg.add_argument(
        "--version",
        default=None,
        help="Optional version filter",
    )
    pkg_install_conan_cfg.add_argument(
        "--build",
        choices=["missing", "never"],
        default="missing",
        help="Conan build policy (default: missing)",
    )
    pkg_install_conan_cfg.add_argument(
        "--force",
        action="store_true",
        help="Force reinstall by clearing the cached Conan package folder first",
    )
    pkg_install_conan_cfg.add_argument(
        "--all",
        action="store_true",
        help=(
            "Install Conan packages for all JSON files in the current directory "
            "that declare the Exodus project schema"
        ),
    )

    pkg_install_conan = pkg_subparsers.add_parser(
        "install-conan",
        help=(
            "Install a single Conan package into EXODUS_CACHE "
            "without modifying exodus.json"
        ),
    )
    pkg_install_conan.add_argument("name", help="Conan package name")
    pkg_install_conan.add_argument(
        "--arch",
        required=True,
        help="Conan arch setting (e.g. x86_64, armv8)",
    )
    pkg_install_conan.add_argument(
        "--version",
        required=True,
        help="Conan package version",
    )
    pkg_install_conan.add_argument(
        "--user", default=None, help="Optional Conan user"
    )
    pkg_install_conan.add_argument(
        "--channel", default=None, help="Optional Conan channel"
    )
    pkg_install_conan.add_argument(
        "--profile", default=None, help="Optional Conan host profile"
    )
    pkg_install_conan.add_argument(
        "--build-profile", default=None, help="Optional Conan build profile"
    )
    pkg_install_conan.add_argument(
        "--remote", default=None, help="Optional Conan remote"
    )
    pkg_install_conan.add_argument(
        "--build",
        choices=["missing", "never"],
        default="missing",
        help="Conan build policy (default: missing)",
    )
    pkg_install_conan.add_argument(
        "--force",
        action="store_true",
        help="Force reinstall by clearing the cached Conan package folder first",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Configure logging
    # from .logger import configure_logging
    configure_logging(args.log_level)

    # Dispatch to tool
    tool: Any = None
    if args.command == "build":
        # from ..tools.build import BuildTool

        tool = BuildTool(args)
        sys.exit(tool.run())
    elif args.command == "clean":
        # from ..tools.clean import CleanTool

        tool = CleanTool(args)
        tool.run()
    elif args.command == "init":
        # from ..tools.init import InitTool

        tool = InitTool(args)
        tool.run()
    elif args.command == "analyze":
        # from ..tools.analyze import AnalyzeTool

        tool = AnalyzeTool(args)
        sys.exit(tool.run())
    elif args.command == "deps":
        # from ..tools.deps import DepsTool

        tool = DepsTool(args)
        tool.run()
    elif args.command == "extract":
        tool = ExtractTool(args)
        sys.exit(tool.run())
    elif args.command == "sbom":
        tool = SbomTool(args)
        sys.exit(tool.run())
    elif args.command == "aiml-diagram":
        tool = AimlDiagramTool(args)
        sys.exit(tool.run())
    elif args.command == "pkg":
        tool = PackageManager(args)
        sys.exit(tool.run())


if __name__ == "__main__":
    main()
