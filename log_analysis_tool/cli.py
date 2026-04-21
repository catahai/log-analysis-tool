from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface for the log analysis tool."""

    parser = argparse.ArgumentParser(
        description="Parse Linux auth.log SSH events and detect suspicious activity."
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        type=Path,
        help="Path to the auth.log file to analyze",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        type=Path,
        default=None,
        help="Path to the auth.log file to analyze",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to use when parsing auth.log timestamps",
    )
    parser.add_argument(
        "--json-out",
        "--output-json",
        type=Path,
        default=Path("output/alerts.json"),
        help="Path for the JSON alert export",
    )
    parser.add_argument(
        "--csv-out",
        "--output-csv",
        type=Path,
        default=Path("output/alerts.csv"),
        help="Path for the CSV alert export",
    )
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate simple SVG charts from the detections",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("output/report"),
        help="Directory for generated chart files",
    )
    return parser
