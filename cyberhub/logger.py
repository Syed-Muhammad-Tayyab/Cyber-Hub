"""
Cyber Hub Backend - Logging
Developed by Syed Muhammad Tayyab

Rotating file log (logs/cyberhub.log) + console output.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    log = logging.getLogger("cyberhub")
    if log.handlers:          # already configured (tests create several apps)
        return log
    log.setLevel(level)
    fmt = logging.Formatter(_FORMAT)

    fh = RotatingFileHandler(log_dir / "cyberhub.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    log.addHandler(ch)
    log.propagate = False
    return log


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"cyberhub.{name}")
