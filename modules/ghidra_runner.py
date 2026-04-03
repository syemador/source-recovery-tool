"""
Ghidra Runner Module
====================
Invokes Ghidra in headless mode to analyze a binary and extract function data.

Two-pass approach:
  Pass 1 (enumerate): List all functions with addresses and names.
  Pass 2 (extract):   Deep-extract features for a selected function.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


# Paths to our Ghidra scripts
SCRIPT_DIR = Path(__file__).parent.parent / "ghidra_scripts"
ENUMERATE_SCRIPT = SCRIPT_DIR / "enumerate_functions.py"
EXTRACT_SCRIPT = SCRIPT_DIR / "extract_features.py"


class GhidraRunner:
    """Manages Ghidra headless execution."""

    def __init__(self, ghidra_path: str, project_dir: str = ""):
        self.ghidra_path = Path(ghidra_path)
        self.project_dir = Path(project_dir) if project_dir else Path(tempfile.mkdtemp())
        self.project_dir.mkdir(parents=True, exist_ok=True)

        # Locate analyzeHeadless
        if sys.platform == "win32":
            self.headless_bin = self.ghidra_path / "support" / "analyzeHeadless.bat"
        else:
            self.headless_bin = self.ghidra_path / "support" / "analyzeHeadless"

        if not self.headless_bin.exists():
            raise FileNotFoundError(
                f"analyzeHeadless not found at {self.headless_bin}. "
                f"Check your GHIDRA_HOME path."
            )

    def _run_headless(
        self,
        binary_path: str,
        script_path: str,
        script_args: list[str] | None = None,
        project_name: str = "SourceRecovery",
    ) -> str:
        """Execute a Ghidra headless script and return stdout."""
        cmd = [
            str(self.headless_bin),
            str(self.project_dir),
            project_name,
            "-import", binary_path,
            "-overwrite",
            "-postScript", str(script_path),
        ]
        if script_args:
            for arg in script_args:
                cmd.append(arg)

        # Disable GUI
        env = os.environ.copy()
        env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + " -Djava.awt.headless=true"

        print(f"    [Ghidra] Running: {Path(script_path).name}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Ghidra analysis timed out (10 min).")
        except FileNotFoundError:
            raise RuntimeError(
                f"Could not execute Ghidra. Verify path: {self.headless_bin}"
            )

        if result.returncode != 0:
            # Ghidra sometimes returns non-zero but still works; check output
            stderr_lower = result.stderr.lower() if result.stderr else ""
            if "error" in stderr_lower and "import" not in stderr_lower:
                raise RuntimeError(
                    f"Ghidra failed (rc={result.returncode}):\n{result.stderr[-2000:]}"
                )

        return result.stdout

    def _parse_json_from_output(self, stdout: str, marker: str = "===JSON_START===") -> dict:
        """Extract JSON payload from Ghidra script stdout using markers."""
        end_marker = "===JSON_END==="
        start_idx = stdout.find(marker)
        end_idx = stdout.find(end_marker)
        if start_idx == -1 or end_idx == -1:
            # Try to find raw JSON as fallback
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
            raise RuntimeError(
                "Could not find JSON output from Ghidra script.\n"
                f"Last 1000 chars of output:\n{stdout[-1000:]}"
            )

        json_str = stdout[start_idx + len(marker):end_idx].strip()
        return json.loads(json_str)

    def run_analysis(self, binary_path: str) -> dict:
        """
        Run the enumeration script to discover all functions.
        Returns dict with 'functions' list.
        """
        stdout = self._run_headless(binary_path, str(ENUMERATE_SCRIPT))
        return self._parse_json_from_output(stdout)

    def extract_function_features(
        self, binary_path: str, function_address: str
    ) -> dict:
        """
        Run the feature extraction script for a specific function.
        Returns dict with detailed features.
        """
        stdout = self._run_headless(
            binary_path,
            str(EXTRACT_SCRIPT),
            script_args=[function_address],
        )
        return self._parse_json_from_output(stdout)
