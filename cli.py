#!/usr/bin/env python3
"""Backward-compatible positional CLI for the unified dispatcher."""

import sys

from interactive import main as interactive_main


# Legacy command names remain available without duplicating engine calls.
LEGACY_COMMANDS = {
    'interfaces': ('--get-interfaces',),
    'select': ('--select-interface',),
    'enable-monitor': ('--enable-monitor',),
    'disable-monitor': ('--disable-monitor',),
    'scan': ('--scan',),
    'deauth': ('--deauth',),
    'handshake': ('--handshake',),
    'crack': ('--crack',),
    'monitor': ('--monitor',),
    'ai': ('--ai-anomaly',),
    'dev-automate': ('--dev-automate',),
}


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print(f"Usage: {sys.argv[0]} <command> [options]")
        print("Commands: " + ", ".join(LEGACY_COMMANDS))
        return 1

    command, *options = arguments
    mapped = LEGACY_COMMANDS.get(command)
    if mapped is None:
        print(f"Unknown command: {command}", file=sys.stderr)
        return 1
    return interactive_main([*mapped, *options])


if __name__ == '__main__':
    sys.exit(main())
