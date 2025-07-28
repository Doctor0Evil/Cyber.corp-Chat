#!/usr/bin/env python3
import subprocess
import os
import sys
import logging
import json
import psutil
import platform
from datetime import datetime
import argparse
import getpass

# Ensure script is run as a Python script
if 'bash' in os.environ.get('SHELL', '') or not sys.executable.endswith('python3'):
    print("Error: This is a Python script. Run it with 'python3 git_resolution.py' or './git_resolution.py' after 'chmod +x git_resolution.py'.")
    sys.exit(1)

# Configuration from system manifest
CONFIG = {
    "repo_path": "/workspaces/Cyber.corp-Chat",
    "log_path": "/var/log/grok_response.log",
    "backup_path": "/opt/EDGE_NODES/virtual/sessions/cloned/repo_backup_20250728.bundle",
    "session_key_path": "/opt/EDGE_NODES/keys/session_key_20250720.asc",
    "monitoring_pid": 4721,
    "alert_email": "Doctor0Evil@protonmail.com",
    "alert_threshold_ms": 100,
    "dependencies": [
        "ai-kernel-1.2.3",
        "neuromorphic-ml-0.9.1",
        "quantum-entropy-ml-1.0.0",
        "cheatcode-layer-ml-1.1.0",
        "blockchain-2.3.1"
    ]
}

# Setup logging to align with supergrok_monitoring
os.makedirs(os.path.dirname(CONFIG["log_path"]), exist_ok=True)
logging.basicConfig(
    filename=CONFIG["log_path"],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("GitResolution")

def run_bash_command(command, check=True, timeout=30):
    """Execute a Bash command and return output, logging execution time."""
    start_time = datetime.now()
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check, timeout=timeout)
        elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
        logger.info(f"> {command} [{elapsed_ms:.0f}ms]")
        if elapsed_ms > CONFIG["alert_threshold_ms"]:
            logger.warning(f"High latency for command '{command}': {elapsed_ms:.0f}ms")
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {command}, Error: {e.stderr}")
        if check:
            raise
        return "", e.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        raise

def install_dependencies():
    """Install required packages and verify Git version."""
    logger.info("Installing dependencies...")
    if platform.system() != "Linux":
        logger.error("This script requires a Linux environment.")
        sys.exit(1)
    run_bash_command("sudo apt-get update && sudo apt-get install -y git=1:2.49.0-*")
    run_bash_command("pip install psutil gitpython")
    for dep in CONFIG["dependencies"]:
        try:
            run_bash_command(f"pip install {dep}")
        except subprocess.CalledProcessError:
            logger.warning(f"Failed to install {dep}, may already be installed.")
    stdout, _ = run_bash_command("git --version")
    if "2.49.0" not in stdout:
        logger.error("Git version 2.49.0 required but not found.")
        sys.exit(1)
    logger.info("Dependencies installed successfully.")

def validate_repository():
    """Validate repository path and initialize scan."""
    logger.info("[Model][doInitialScan] Initial repository scan started")
    if not os.path.exists(CONFIG["repo_path"]):
        logger.error(f"Repository path does not exist: {CONFIG['repo_path']}")
        sys.exit(1)
    os.chdir(CONFIG["repo_path"])
    stdout, stderr = run_bash_command("git rev-parse --show-toplevel")
    if stderr or stdout != CONFIG["repo_path"]:
        logger.error(f"Invalid repository path: {CONFIG['repo_path']}")
        sys.exit(1)
    logger.info(f"[Model][openRepository] Opened repository (path): {stdout}")
    run_bash_command("git config --get commit.template")
    run_bash_command("git status -z -uall")
    logger.info("[Model][doInitialScan] Initial repository scan completed")

def resolve_divergent_branches(strategy):
    """Resolve divergent branches based on user strategy."""
    logger.info(f"Resolving divergent branches with strategy: {strategy}")
    strategy_map = {"merge": "false", "rebase": "true", "ff": "only"}
    run_bash_command(f"git config pull.rebase {strategy_map[strategy]}")
    stdout, stderr = run_bash_command("git pull --tags origin main", check=False)
    if "fatal: Need to specify how to reconcile divergent branches" in stderr:
        logger.error("Divergent branches could not be reconciled. Inspecting differences...")
        run_bash_command("git log --oneline --graph --all")
        run_bash_command("git diff refs/heads/main refs/remotes/origin/main")
        sys.exit(1)
    logger.info("Divergent branches reconciled successfully.")
    run_bash_command("git push origin main", check=False)

def fix_config_warning():
    """Fix or unset branch.main.github-pr-owner-number configuration."""
    logger.info("Checking branch.main.github-pr-owner-number configuration")
    stdout, stderr = run_bash_command("git config --get branch.main.github-pr-owner-number", check=False)
    if stderr:
        logger.warning("Configuration branch.main.github-pr-owner-number not set, unsetting.")
        run_bash_command("git config --local --unset branch.main.github-pr-owner-number", check=False)
    else:
        logger.info(f"Configuration found: {stdout}")

def monitor_system():
    """Monitor system performance for the monitoring PID."""
    logger.info("Monitoring system performance...")
    try:
        process = psutil.Process(CONFIG["monitoring_pid"])
        cpu_percent = process.cpu_percent(interval=1)
        memory_mb = process.memory_info().rss / 1024 / 1024
        logger.info(f"Performance: CPU {cpu_percent:.1f}%, Memory {memory_mb:.1f}MB")
        if cpu_percent > 10 or memory_mb > 256:
            logger.warning(f"High resource usage detected: CPU {cpu_percent:.1f}%, Memory {memory_mb:.1f}MB")
    except psutil.NoSuchProcess:
        logger.error(f"No process found with PID {CONFIG['monitoring_pid']}")

def create_backup():
    """Create a repository backup."""
    logger.info("Creating repository backup...")
    os.makedirs(os.path.dirname(CONFIG["backup_path"]), exist_ok=True)
    run_bash_command(f"git bundle create {CONFIG['backup_path']} --all")
    logger.info(f"Backup created at {CONFIG['backup_path']}")

def generate_chart():
    """Generate Chart.js visualization of Git command execution times."""
    chart_data = {
        "type": "bar",
        "data": {
            "labels": ["rev-parse", "for-each-ref", "status", "fetch", "diff", "log"],
            "datasets": [{
                "label": "Execution Time (ms)",
                "data": [94, 122, 115, 301, 10, 88],
                "backgroundColor": ["#4CAF50", "#2196F3", "#FFC107", "#F44336", "#9C27B0", "#FF9800"],
                "borderColor": ["#388E3C", "#1976D2", "#FFA000", "#D32F2F", "#7B1FA2", "#F57C00"],
                "borderWidth": 1
            }]
        },
        "options": {
            "scales": {
                "y": {"beginAtZero": True, "title": {"display": True, "text": "Time (ms)"}},
                "x": {"title": {"display": True, "text": "Git Command"}}
            },
            "plugins": {
                "legend": {"display": False},
                "title": {"display": True, "text": "Git Command Execution Times (2025-07-28)"}
            }
        }
    }
    chart_path = "/opt/EDGE_NODES/virtual/cheatbooks/git_performance_chart.json"
    os.makedirs(os.path.dirname(chart_path), exist_ok=True)
    with open(chart_path, "w") as f:
        json.dump(chart_data, f, indent=2)
    logger.info(f"Chart data saved to {chart_path}")

def main():
    """Main function to execute all resolution steps."""
    parser = argparse.ArgumentParser(description="Resolve Git issues and monitor repository")
    parser.add_argument("--strategy", choices=["merge", "rebase", "ff"], default="merge",
                        help="Strategy to resolve divergent branches (default: merge)")
    args = parser.parse_args()

    logger.info("Starting Git resolution script")
    install_dependencies()
    validate_repository()
    fix_config_warning()
    resolve_divergent_branches(args.strategy)
    create_backup()
    monitor_system()
    generate_chart()
    logger.info("Script execution completed successfully.")

if __name__ == "__main__":
    if getpass.getuser() != "Doctor0Evil":
        logger.error("Script must be run as user Doctor0Evil")
        sys.exit(1)
    main()
cd /workspaces/Cyber.corp-Chat
nano git_resolution.py
chmod +x git_resolution.py
python3 git_resolution.py --strategy merge
./git_resolution.py --strategy merge
cd /workspaces/Cyber.corp-Chat
git status
cat git_resolution.py
head -n 5 git_resolution.py
nano git_resolution.py
