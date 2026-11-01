"""Sentinel's command-line interface."""

import argparse
import re
import sys
import zlib
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .models import DetectionConfig
from .parser import parse_utc_offset
from .report import render_json, render_text, safe_text


def _threshold(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threshold must be an integer of at least 2") from exc
    if number < 2:
        raise argparse.ArgumentTypeError("threshold must be at least 2")
    return number


def _duration(value: str) -> int:
    match = re.fullmatch(r"([0-9]{1,8})([smh]?)", value)
    if not match or int(match[1]) == 0:
        raise argparse.ArgumentTypeError("window must be a positive duration, e.g. 300, 30s, 5m, or 1h")
    return int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]


def _year(value: str) -> int:
    try:
        year = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("year must be an integer between 1 and 9999") from exc
    if not 1 <= year <= 9999:
        raise argparse.ArgumentTypeError("year must be between 1 and 9999")
    return year


def _offset(value: str) -> str:
    try:
        parse_utc_offset(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel", description="Find suspicious SSH authentication patterns in Linux log exports."
    )
    parser.add_argument("--version", action="version", version=f"Sentinel {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("analyze", help="analyze files, .gz files, or '-' for stdin")
    command.add_argument("files", nargs="+", help="input paths; records must not overlap between files")
    command.add_argument("--threshold", type=_threshold, default=5, help="failed attempts needed (default: 5)")
    command.add_argument("--window", type=_duration, default=300, help="sliding window (default: 5m)")
    command.add_argument("--spray-threshold", type=_threshold, default=3, help="distinct failed usernames needed (default: 3)")
    command.add_argument("--year", type=_year, help="starting year per yearless syslog file (default: current UTC year)")
    command.add_argument("--utc-offset", type=_offset, default="+00:00", help="offset for timestamps without a zone (default: +00:00)")
    command.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    command.add_argument("--output", type=Path, help="write report to this file instead of stdout")
    command.add_argument("--fail-on-alert", action="store_true", help="exit 1 when alerts are found; input errors still exit 2")
    return parser


def _validate_paths(files: list[str], output: Path | None) -> None:
    paths = [Path(name).resolve() for name in files if name != "-"]
    if len(paths) != len(set(paths)):
        raise ValueError("the same input file was supplied more than once")
    if files.count("-") > 1:
        raise ValueError("stdin can only be read once")
    if output is not None:
        resolved = output.resolve()
        for path in paths:
            if resolved == path or (resolved.exists() and path.exists() and resolved.samefile(path)):
                raise ValueError("output must not overwrite an input log")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _validate_paths(args.files, args.output)
        config = DetectionConfig(args.threshold, args.window, args.spray_threshold)
        report = analyze(args.files, config, year=args.year, utc_offset=args.utc_offset, stdin=sys.stdin)
        result = render_json(report) if args.format == "json" else render_text(report)
        if args.output is None:
            sys.stdout.write(result)
        else:
            args.output.write_text(result, encoding="utf-8")
        if report.status != "ok":
            print(f"sentinel: analysis status: {report.status}; see report for input coverage", file=sys.stderr)
            return 2
        return 1 if args.fail_on_alert and report.alerts else 0
    except BrokenPipeError:
        return 0
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        print(f"sentinel: {safe_text(str(exc))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("sentinel: interrupted", file=sys.stderr)
        return 130
