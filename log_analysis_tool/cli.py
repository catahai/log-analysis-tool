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
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional JSON file containing detection rule settings",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=None,
        help="Failed login count required to trigger the brute-force rule",
    )
    parser.add_argument(
        "--brute-force-window",
        type=int,
        default=None,
        help="Time window in minutes for the brute-force rule",
    )
    parser.add_argument(
        "--success-threshold",
        type=int,
        default=None,
        help="Failed login count required before a success triggers the follow-on rule",
    )
    parser.add_argument(
        "--success-window",
        type=int,
        default=None,
        help="Time window in minutes for the success-after-failures rule",
    )
    parser.add_argument(
        "--invalid-user-threshold",
        type=int,
        default=None,
        help="Invalid username attempts required to trigger enumeration detection",
    )
    parser.add_argument(
        "--invalid-user-window",
        type=int,
        default=None,
        help="Time window in minutes for invalid username enumeration detection",
    )
    parser.add_argument(
        "--spray-username-threshold",
        type=int,
        default=None,
        help="Distinct usernames from one IP required to trigger password spraying detection",
    )
    parser.add_argument(
        "--spray-window",
        type=int,
        default=None,
        help="Time window in minutes for password spraying detection",
    )
    parser.add_argument(
        "--root-attempt-threshold",
        type=int,
        default=None,
        help="Root login attempts required to trigger root login detection",
    )
    parser.add_argument(
        "--root-attempt-window",
        type=int,
        default=None,
        help="Time window in minutes for root login attempt detection",
    )
    return parser
