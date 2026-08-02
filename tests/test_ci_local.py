import os
import subprocess
from pathlib import Path


def test_fast_pipeline_prints_durable_progress(tmp_path: Path) -> None:
    command_stub = tmp_path / "command-ok"
    command_stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    command_stub.chmod(0o755)

    env = os.environ.copy()
    env.update({"PYTHON": str(command_stub), "SIGMA": str(command_stub)})
    completed = subprocess.run(
        ["bash", "scripts/ci-local.sh", "--fast"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Detection Under Load | local verification pipeline" in completed.stdout
    assert "[----------------------------]   0% | READY | pipeline initialized" in completed.stdout
    assert "0% | RUN" in completed.stdout
    assert "command:" in completed.stdout
    assert "100% | PASS" in completed.stdout
    assert "summary: 4 passed, 0 failed" in completed.stdout
    assert completed.stdout.rstrip().endswith("all jobs passed")
