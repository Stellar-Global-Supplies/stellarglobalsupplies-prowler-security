#!/usr/bin/env python3
"""
apply_patch.py
==============

Applies the ``json-results`` exporter patch to an installed Prowler package.

Usage (run once after ``pip install prowler``):

    python apply_patch.py [--prowler-root /path/to/prowler/package]

What it does:
1. Copies ``prowler/lib/outputs/json_results/`` into the installed package.
2. Adds ``json-results`` to ``available_output_formats`` in ``config/config.py``.
3. Registers the format in ``prowler/__main__.py``.

All changes are idempotent – running the script twice is safe.
"""

from __future__ import annotations

import importlib.util
import shutil
import site
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Locate the installed Prowler package
# ---------------------------------------------------------------------------

def find_prowler_root(override: str | None = None) -> Path:
    if override:
        root = Path(override)
        if not (root / "__init__.py").exists():
            sys.exit(f"ERROR: {root} does not look like a prowler package directory.")
        return root

    spec = importlib.util.find_spec("prowler")
    if spec is None or spec.origin is None:
        sys.exit(
            "ERROR: prowler is not importable. "
            "Activate the right virtualenv or pass --prowler-root."
        )
    return Path(spec.origin).parent


# ---------------------------------------------------------------------------
# Step 1 – Copy exporter module
# ---------------------------------------------------------------------------

def install_exporter(prowler_root: Path, patch_dir: Path) -> None:
    src = patch_dir / "prowler" / "lib" / "outputs" / "json_results"
    dst = prowler_root / "lib" / "outputs" / "json_results"

    if dst.exists():
        print(f"  [SKIP] {dst} already exists — removing and re-copying.")
        shutil.rmtree(dst)

    shutil.copytree(src, dst)
    print(f"  [OK]   Copied exporter to {dst}")


# ---------------------------------------------------------------------------
# Step 2 – Patch config.py
# ---------------------------------------------------------------------------

_CONFIG_MARKER = '"json-results"'
_CONFIG_OLD = 'available_output_formats = ["csv", "json-asff", "json-ocsf", "html", "sarif"]'
_CONFIG_NEW = 'available_output_formats = ["csv", "json-asff", "json-ocsf", "html", "sarif", "json-results"]'


def patch_config(prowler_root: Path) -> None:
    config_path = prowler_root / "config" / "config.py"
    text = config_path.read_text(encoding="utf-8")

    if _CONFIG_MARKER in text:
        print("  [SKIP] config.py already contains 'json-results'.")
        return

    if _CONFIG_OLD not in text:
        sys.exit(
            f"ERROR: Could not find expected line in {config_path}.\n"
            "The installed Prowler version may differ from the one this patch targets.\n"
            f"Expected:\n  {_CONFIG_OLD}"
        )

    text = text.replace(_CONFIG_OLD, _CONFIG_NEW)
    config_path.write_text(text, encoding="utf-8")
    print(f"  [OK]   Patched {config_path}")


# ---------------------------------------------------------------------------
# Step 3 – Patch __main__.py
# ---------------------------------------------------------------------------

_MAIN_IMPORT_MARKER = "from prowler.lib.outputs.json_results.json_results import JSONResults"

_MAIN_IMPORT_ANCHOR = "from prowler.lib.outputs.sarif.sarif import SARIF"
_MAIN_IMPORT_ADDITION = (
    "from prowler.lib.outputs.sarif.sarif import SARIF\n"
    "from prowler.lib.outputs.json_results.json_results import JSONResults"
)

_MAIN_SUFFIX_MARKER = 'json_results_file_suffix = ".results.json"'
_MAIN_SUFFIX_ANCHOR = "from prowler.config.config import ("
_MAIN_SUFFIX_ANCHOR_END = ")"

# The block we inject into the output-format dispatch loop
# The json-results dispatch must run UNCONDITIONALLY — even when
# finding_outputs is empty (zero resources found).  Prowler wraps the
# output-format loop in ``if finding_outputs:``, so a no-resource scan
# would otherwise skip our exporter entirely and leave a 0-byte file.
# We therefore inject the block at the top level, right before the
# ``push_to_cloud`` handling, instead of inside the per-mode loop.
#
# Variable-scope notes (verified against prowler/__main__.py):
#   * ``filename`` is computed INSIDE the ``for mode in args.output_formats:``
#     loop, so it is NOT available here — we rebuild the path inline from
#     ``output_options``.
#   * ``args.output_formats`` / ``output_options`` / ``finding_outputs`` /
#     ``generated_outputs`` are all in scope at the ``push_to_cloud`` anchor.
_MAIN_DISPATCH_MARKER = 'if "json-results" in (args.output_formats or []):'
_MAIN_DISPATCH_ANCHOR = '    if getattr(args, "push_to_cloud", False):'
_MAIN_DISPATCH_BLOCK = '''\
    if "json-results" in (args.output_formats or []):
        json_results_output = JSONResults(
            findings=finding_outputs,
            file_path=(
                f"{output_options.output_directory}/"
                f"{output_options.output_filename}.results.json"
            ),
        )
        generated_outputs["regular"].append(json_results_output)
        json_results_output.batch_write_data_to_file()

'''

# Legacy in-loop dispatch block from older versions of this patch.  If it is
# present we remove it so the exporter is not instantiated twice (once in the
# loop, once unconditionally).
_OLD_DISPATCH_BLOCK = '''\
            if mode == "json-results":
                json_results_output = JSONResults(
                    findings=finding_outputs,
                    file_path=f"{filename}.results.json",
                )
                generated_outputs["regular"].append(json_results_output)
                json_results_output.batch_write_data_to_file()

'''

# Config import addition
_MAIN_CONFIG_IMPORT_MARKER = "json_results_file_suffix"
_MAIN_CONFIG_IMPORT_ANCHOR = "    sarif_file_suffix,"
_MAIN_CONFIG_IMPORT_ADDITION = "    sarif_file_suffix,\n    json_results_file_suffix,"


def patch_main(prowler_root: Path) -> None:
    main_path = prowler_root / "__main__.py"
    text = main_path.read_text(encoding="utf-8")
    changed = False

    # 2a. Add import
    if _MAIN_IMPORT_MARKER not in text:
        if _MAIN_IMPORT_ANCHOR not in text:
            sys.exit(
                f"ERROR: Cannot find import anchor in {main_path}.\n"
                f"Expected to find: {_MAIN_IMPORT_ANCHOR}"
            )
        text = text.replace(_MAIN_IMPORT_ANCHOR, _MAIN_IMPORT_ADDITION)
        changed = True
        print(f"  [OK]   Added JSONResults import in {main_path}")
    else:
        print("  [SKIP] JSONResults import already present in __main__.py")

    # 2b. Remove legacy in-loop dispatch block if present (from a previous
    #     version of this patch).  Keeping it would instantiate the exporter
    #     twice — once inside the ``if finding_outputs:`` loop and once in
    #     our new unconditional block.
    if _OLD_DISPATCH_BLOCK in text:
        text = text.replace(_OLD_DISPATCH_BLOCK, "")
        changed = True
        print(f"  [OK]   Removed legacy in-loop json-results dispatch block from {main_path}")

    # 2c. Add unconditional dispatch block (runs even with zero findings so
    #     a no-resource scan still produces a valid JSON envelope).
    if _MAIN_DISPATCH_MARKER not in text:
        if _MAIN_DISPATCH_ANCHOR not in text:
            sys.exit(
                f"ERROR: Cannot find dispatch anchor in {main_path}.\n"
                f"Expected to find: {_MAIN_DISPATCH_ANCHOR}"
            )
        text = text.replace(_MAIN_DISPATCH_ANCHOR, _MAIN_DISPATCH_BLOCK + _MAIN_DISPATCH_ANCHOR)
        changed = True
        print(f"  [OK]   Added unconditional json-results dispatch block in {main_path}")
    else:
        print("  [SKIP] json-results dispatch block already present in __main__.py")

    if changed:
        main_path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Step 4 – Patch summary_table.py (add file path mention in summary)
# ---------------------------------------------------------------------------

_SUMMARY_MARKER = '"json-results"'
_SUMMARY_ANCHOR = '            if "sarif" in output_options.output_modes:'
_SUMMARY_BLOCK = '''\
            if "json-results" in output_options.output_modes:
                print(
                    f" - JSON-Results: {output_directory}/{output_filename}.results.json"
                )
'''


def patch_summary_table(prowler_root: Path) -> None:
    summary_path = prowler_root / "lib" / "outputs" / "summary_table.py"
    if not summary_path.exists():
        print(f"  [SKIP] {summary_path} not found — skipping summary_table patch.")
        return

    text = summary_path.read_text(encoding="utf-8")

    if _SUMMARY_MARKER in text:
        print("  [SKIP] summary_table.py already patched.")
        return

    if _SUMMARY_ANCHOR not in text:
        print(
            f"  [WARN] Cannot find anchor in {summary_path} — "
            "summary_table.py not patched (non-fatal)."
        )
        return

    text = text.replace(_SUMMARY_ANCHOR, _SUMMARY_BLOCK + _SUMMARY_ANCHOR)
    summary_path.write_text(text, encoding="utf-8")
    print(f"  [OK]   Patched {summary_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Step 5 – Install custom Cloudflare services (workers, pages, d1, kv)
# ---------------------------------------------------------------------------

CUSTOM_SERVICES = ["workers", "pages", "d1", "kv"]


def install_custom_cf_services(prowler_root: Path, patch_dir: Path) -> None:
    """Copy custom Cloudflare service packages into the installed provider.

    The custom services live in the repo root ``prowler/providers/cloudflare/
    services`` (tracked in git).  ``patch_dir`` is ``prowler_patches/``, so we
    first try the repo-root location (one level up from ``patch_dir``) and
    fall back to ``prowler_patches/prowler/providers/...`` for backwards
    compatibility with older layouts.
    """
    cf_services_dst = prowler_root / "providers" / "cloudflare" / "services"

    # Preferred: repo root prowler/providers/cloudflare/services
    repo_root = patch_dir.parent
    cf_services_src = repo_root / "prowler" / "providers" / "cloudflare" / "services"
    if not cf_services_src.exists():
        # Fallback: prowler_patches/prowler/providers/cloudflare/services
        cf_services_src = patch_dir / "prowler" / "providers" / "cloudflare" / "services"

    if not cf_services_src.exists():
        print(f"  [SKIP] No custom CF services found in {cf_services_src}")
        return

    for svc in CUSTOM_SERVICES:
        src = cf_services_src / svc
        dst = cf_services_dst / svc
        if not src.exists():
            print(f"  [SKIP] {svc}: source not found at {src}")
            continue
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        check_count = sum(1 for d in dst.iterdir() if d.is_dir() and not d.name.startswith("_"))
        print(f"  [OK]   Installed '{svc}' service ({check_count} checks) → {dst}")

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Apply json-results patch to Prowler.")
    parser.add_argument(
        "--prowler-root",
        default=None,
        help="Path to the prowler package directory (auto-detected if omitted).",
    )
    args = parser.parse_args()

    prowler_root = find_prowler_root(args.prowler_root)
    patch_dir = Path(__file__).parent

    print(f"\nProwler root : {prowler_root}")
    print(f"Patch source : {patch_dir}\n")

    print("Step 1 – Installing exporter module …")
    install_exporter(prowler_root, patch_dir)

    print("Step 2 – Patching config/config.py …")
    patch_config(prowler_root)

    print("Step 3 – Patching __main__.py …")
    patch_main(prowler_root)

    print("Step 4 – Patching lib/outputs/summary_table.py …")
    patch_summary_table(prowler_root)

    print("Step 5 – Installing custom Cloudflare services …")
    install_custom_cf_services(prowler_root, patch_dir)

    print("\n✅  Patch applied successfully.\n")
    print("Test with:")
    print("  prowler aws         --output-formats json-results --output-directory ./output")
    print("  prowler cloudflare  --output-formats json-results --output-directory ./output\n")


if __name__ == "__main__":
    main()