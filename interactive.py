#!/usr/bin/env python3
"""
Network Analyzer Interactive Engine 
"""
import argparse
import sys
import webbrowser
from pathlib import Path
from engines.core import NetworkAnalyzerCore
from engines.monitor import MonitorEngine
from engines.discovery import DiscoveryEngine
from engines.deauth import DeauthEngine
from engines.handshake import HandshakeEngine
from engines.crack import CrackEngine
from engines.terminal_manager import TerminalManager
from engines.ai_anomaly import AIAnomalyEngine
from engines.enhanced_monitor import EnhancedMonitor
from engines.dev_automate import DevAutomate
from engines.wifi_clients import build_monitor_command
from engines.utils import (
    print_colored, input_colored, VERSION, setup_logging, cleanup,
    auto_install_missing_tools, auto_install_missing_python_packages,
)

PROJECT_WEBSITE = "https://guang84.github.io/"


def _open_project_website() -> None:
    """Open the project home page without delaying terminal startup."""
    try:
        webbrowser.open(PROJECT_WEBSITE, new=2, autoraise=True)
    except webbrowser.Error:
        # A browser is optional; the terminal application remains usable.
        pass

def _select_scan_file(core, prompt="Select scan file: "):
    """Return a user-selected JSON scan path, or None."""
    scan_dir = Path(core.config.get('output_dirs', {}).get('scans', './scans'))
    files = sorted(scan_dir.glob('*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
    if not files:
        print_colored("No saved JSON scan data found.", "yellow")
        return None
    for index, path in enumerate(files, 1):
        print_colored(f"  {index}. {path.name}", "white")
    choice = input_colored(f"{prompt}(q cancels): ", "green").strip()
    if choice.lower() == 'q':
        return None
    try:
        selected = int(choice)
        if not 1 <= selected <= len(files):
            raise IndexError
        return files[selected - 1]
    except (ValueError, IndexError):
        print_colored("Invalid scan selection.", "red")
        return None


def _show_incidents(ai, limit=20):
    incidents = ai.store.recent_incidents(limit)
    if not incidents:
        print_colored("No anomaly incidents have been recorded.", "green")
        return
    print_colored("\nRECENT ANOMALY INCIDENTS", "cyan", bold=True)
    for item in incidents:
        from datetime import datetime
        observed = datetime.fromtimestamp(item['detected_at']).strftime('%Y-%m-%d %H:%M:%S')
        print_colored(
            f"#{item['id']} {observed} [{item['severity'].upper():8}] [{item['status']}] {item['rule']}: {item['message']}",
            "red" if item['severity'] in ('critical', 'high') else "yellow",
        )


def ai_anomaly_menu(core):
    """Sub-menu for learning, replay, triage, and live anomaly detection."""
    ai = AIAnomalyEngine(core)
    try:
        _ai_anomaly_menu(core, ai)
    finally:
        ai.store.close()


def _ai_anomaly_menu(core, ai):
    while True:
        print_colored("\nAI ANOMALY DETECTION", "cyan", bold=True)
        print_colored("═" * 62, "cyan")
        print_colored("  1. Start passive live detection", "white")
        print_colored("  2. Import saved scans and train", "white")
        print_colored("  3. Replay a saved scan against learned patterns", "white")
        print_colored("  4. Review recent incidents", "white")
        print_colored("  5. Mark a learned BSSID as trusted", "white")
        print_colored("  6. Show pattern database statistics", "white")
        print_colored("  7. Export anomaly incidents", "white")
        print_colored("  8. Back to main menu", "white")
        print_colored("  9. Update incident status", "white")
        print_colored("  10. Revoke BSSID trust", "white")
        print_colored("  11. Approve latest BSSID observation as baseline", "white")
        print_colored("═" * 62, "cyan")
        choice = input_colored("Select option: ", "green")
        if choice == '1':
            ai.run_live_monitoring()
        elif choice == '2':
            scan_dir = Path(core.config.get('output_dirs', {}).get('scans', './scans'))
            json_files = sorted(scan_dir.glob("*.json"))
            if not json_files:
                print_colored("No saved scan data found.", "yellow")
                continue
            result = ai.import_scan_files(json_files)
            print_colored(
                f"Imported {result['imported']} scan(s); skipped {result['skipped']}.", "green"
            )
        elif choice == '3':
            path = _select_scan_file(core, "Replay which scan? ")
            if path:
                try:
                    incidents = ai.replay_scan(path)
                    ai._live_report(incidents, ai.snapshot_from_scan_file(path))
                except (OSError, ValueError, TypeError) as exc:
                    print_colored(f"Unable to replay scan: {exc}", "red")
        elif choice == '4':
            _show_incidents(ai)
        elif choice == '5':
            patterns = ai.store.learned_patterns()
            if patterns:
                print_colored("Recently learned BSSIDs:", "cyan")
                for item in patterns:
                    marker = "trusted" if item['trusted'] else "candidate"
                    print_colored(
                        f"  {item['bssid']}  {item['essid']}  {item['security']}  [{marker}]",
                        "white",
                    )
            else:
                print_colored("Import or capture observations before creating a trusted baseline.", "yellow")
                continue
            bssid = input_colored("Learned BSSID to trust (blank cancels): ", "green").strip()
            if bssid:
                if ai.trust_bssid(bssid):
                    print_colored(f"Trusted baseline saved for {bssid.upper()}.", "green")
                else:
                    print_colored("BSSID is not in the learned pattern database.", "yellow")
        elif choice == '6':
            stats = ai.store.stats()
            print_colored("\nPattern Database Statistics", "cyan", bold=True)
            print_colored(f"Database: {ai.db_path}", "white")
            print_colored(f"Snapshots: {stats['snapshots']}", "white")
            print_colored(f"Network observations: {stats['observations']}", "white")
            print_colored(f"Learned BSSIDs: {stats['patterns']} ({stats['trusted_patterns']} trusted)", "white")
            print_colored(f"Incidents: {stats['incidents']} ({stats['open_incidents']} open)", "white")
            print_colored(f"ML model: {'ready' if ai.model else 'not trained'}", "white")
            if ai.baseline:
                print_colored(f"Baseline samples: {ai.baseline.get('sample_count', 'legacy')}", "white")
                print_colored(f"Baseline network count: {ai.baseline.get('avg_count', 0):.1f}", "white")
            print_colored("═" * 40, "cyan")
        elif choice == '7':
            report = ai.export_incidents()
            print_colored(f"Incident report exported: {report}", "green")
        elif choice == '8':
            break
        elif choice == '9':
            _show_incidents(ai)
            try:
                incident_id = int(input_colored("Incident ID: ", "green"))
                status = input_colored("Status (open/acknowledged/resolved): ", "green").strip().lower()
                if not ai.store.set_incident_status(incident_id, status):
                    print_colored("Incident not found.", "yellow")
            except ValueError as exc:
                print_colored(f"Unable to update incident: {exc}", "yellow")
        elif choice == '10':
            bssid = input_colored("BSSID to untrust (blank cancels): ", "green").strip()
            if bssid:
                changed = ai.store.set_trusted(bssid, False)
                print_colored("Trust revoked." if changed else "BSSID not found.", "yellow")
        elif choice == '11':
            bssid = input_colored("BSSID to refresh (blank cancels): ", "green").strip()
            if not bssid:
                continue
            latest = ai.store.latest_observation(bssid)
            if latest is None:
                print_colored("No observation found for that BSSID.", "yellow")
                continue
            print_colored(
                f"Approve {latest['bssid']}: SSID {latest['essid']!r}, "
                f"security {latest['security']}, channel {latest['channel']}, "
                f"signal {latest['signal']} dBm", "yellow",
            )
            if input_colored("Trust this observation? [y/N]: ", "green").strip().lower() in ('y', 'yes'):
                ai.store.approve_latest_observation(bssid)
                print_colored("Trusted baseline updated.", "green")
        else:
            print_colored("Invalid option.", "red")


# The interactive menu maps directly to this module's command-line actions.
# Bash deliberately knows nothing about individual features, so adding or
# renaming a menu command only requires a change here.
MENU_OPTIONS = (
    ('0', 'Select/Change Interface', ('--select-interface',), True),
    ('1', 'Enable Monitor Mode ', ('--enable-monitor', '--visual'), False),
    ('2', 'Disable Monitor Mode ', ('--disable-monitor', '--visual'), False),
    ('3', 'Network Discovery ', ('--scan', '--multi-terminal'), True),
    ('4', 'Deauthentication Attack', ('--deauth',), True),
    ('5', 'Capture Handshake', ('--handshake',), True),
    ('6', 'Password Cracking', ('--crack',), True),
    ('7', 'Vulnerability Assessment', ('--vuln',), True),
    ('8', 'Enhanced Network Monitoring', ('--enhanced-monitor',), True),
    ('9', 'AI Anomaly Detection ', ('--ai-menu',), True),
    ('10', 'Analyze Saved Data', ('--analyze',), True),
    ('11', 'Export Report', ('--export',), True),
    ('12', 'Show Terminal Layout', ('--show-layout',), True),
    ('13', 'System Info', ('--sysinfo',), True),
    ('14', 'Run Readiness Diagnostics', ('--doctor',), True),
    ('15', 'Dev Automate (Must TRY ^;)^)', ('--dev-automate',), False),
)

NETWORK_ANALYZER_BANNER = (
    "                                                                  ",
    "    ║█████████║         ║█████║        ║██████████████████║       ",
    "    ║██████████║        ║█████║       ║█████████████████████║     ",
    "    ║██████║ ███║       ║█████║       ║█████║        ║██████║     ",
    "    ║██████║  ███║      ║█████║       ║█████║        ║██████║     ",
    "    ║██████║   ███║     ║█████║       ║█████║        ║██████║     ",
    "    ║██████║    ████    ║█████║       ║█████████████████████║     ",
    "    ║██████║     ███║   ║█████║       ║█████████████████████║     ",
    "    ║██████║      ███║  ║█████║       ║█████║        ║██████║     ",
    "    ║██████║       ███║ ║█████║       ║█████║        ║██████║     ",
    "    ║██████║        ██████████║       ║█████║        ║██████║     ",
    "    ║██████║         █████████║   █   ║█████║        ║██████║     ",
    "                                                                  ",
)


def _show_banner():
    print_colored("╔" + "═" * 76 + "╗", "cyan")
    for line in NETWORK_ANALYZER_BANNER:
        print_colored(line, "green")
    print_colored(f"                NETWORK ANALYZER v{VERSION}", "yellow", bold=True)
    print_colored("       learn more at: https://github.com/Guang84/Network-Analyzer.git", "yellow")
    print_colored(f"     Documentation & Guide Page : {PROJECT_WEBSITE}", "yellow")
    print_colored("╚" + "═" * 76 + "╝", "cyan")


def interactive_menu(core):
    """Run all menu actions in one Python process with one shared core."""
    if main(['--init'], core=core) != 0:
        print_colored("Required package setup did not complete.", "red")
        return 1

    options = {number: (arguments, pause) for number, _, arguments, pause in MENU_OPTIONS}
    while True:
        print_colored("\n" + "═" * 67, "cyan")
        print_colored(f"  MAIN MENU - Network Analyzer v{VERSION}", "green", bold=True)
        print_colored("═" * 67, "cyan")
        print_colored(f"\nActive Interface: {core.active_interface or 'none'}", "yellow")
        print_colored("\nAvailable Interfaces:", "yellow")
        interfaces = core.detect_interfaces()
        if interfaces:
            for interface in interfaces:
                details = core.get_interface_details(interface)
                mode = 'MON' if details.get('is_monitor') else 'MAN'
                current = ' (active)' if interface == core.active_interface else ''
                print_colored(f"  {interface:<14} {mode}{current}", "white")
        else:
            print_colored("  No network interfaces detected.", "red")

        print_colored("\nOPTIONS", "cyan", bold=True)
        for number, label, _, _ in MENU_OPTIONS:
            print_colored(f"  {number:>2}. {label}", "white")
        print_colored("  16. Exit", "red")
        print_colored("\nPress Ctrl+C to exit immediately", "yellow")

        choice = input_colored("\nEnter your choice: ", "green").strip()
        if choice == '16':
            cleanup()
            return 0
        selected = options.get(choice)
        if selected is None:
            print_colored("Invalid option.", "red")
            continue
        arguments, pause_after = selected
        main(list(arguments), core=core)
        if pause_after:
            input_colored("\nPress Enter to return to menu...", "yellow")


def main(argv=None, core=None):
    parser = argparse.ArgumentParser(description='Network Analyzer Interactive Engine')
    parser.add_argument('--menu', action='store_true', help='Open the interactive main menu')
    parser.add_argument('-v', '--version', action='version', version=f'Network Analyzer {VERSION}')
    parser.add_argument('--init', action='store_true', help='Initialize environment')
    parser.add_argument('--get-interfaces', action='store_true', help='List interfaces')
    parser.add_argument('--get-active-interface', action='store_true', help='Show active interface')
    parser.add_argument('--select-interface', action='store_true', help='Select interface interactively')
    parser.add_argument('--enable-monitor', nargs='?', const='', default=None, help='Enable monitor mode on IFACE')
    parser.add_argument('--disable-monitor', action='store_true', help='Disable monitor mode')
    parser.add_argument('--scan', action='store_true', help='Run network scan')
    parser.add_argument('--multi-terminal', action='store_true', help='Use multi‑terminal for scan')
    parser.add_argument('--deauth', action='store_true', help='Run deauthentication attack')
    parser.add_argument('--handshake', action='store_true', help='Capture handshake')
    parser.add_argument('--crack', action='store_true', help='Crack password')
    parser.add_argument('--vuln', action='store_true', help='Vulnerability assessment')
    parser.add_argument('--monitor', action='store_true', help='Multi‑pane network monitoring')
    parser.add_argument('--enhanced-monitor', action='store_true', help='Enhanced interactive monitoring with xterm')
    parser.add_argument('--wifi-clients', action='store_true', help='Passive AP/client monitor in a separate terminal')
    parser.add_argument('--wifi-client-output', type=Path, help='Save passive AP/client observations as JSON')
    parser.add_argument('--ai-anomaly', action='store_true', help='AI anomaly detection (live)')
    parser.add_argument('--ai-menu', action='store_true', help='Open AI anomaly detection menu')
    parser.add_argument('--analyze', action='store_true', help='Analyze saved data')
    parser.add_argument('--export', action='store_true', help='Export report')
    parser.add_argument('--show-layout', action='store_true', help='Show terminal layout')
    parser.add_argument('--sysinfo', action='store_true', help='System information')
    parser.add_argument('--doctor', action='store_true', help='Show readiness diagnostics')
    parser.add_argument('--dev-automate', action='store_true', help='Open automated passive dashboards')
    parser.add_argument('--visual', action='store_true', help='Enable visual feedback')
    command_line = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(command_line)

    if core is None:
        setup_logging()
        core = NetworkAnalyzerCore()

    if args.menu or not command_line:
        _open_project_website()
        _show_banner()
        return interactive_menu(core)

    if args.init:
        python_ready = auto_install_missing_python_packages()
        ready = core.validate_environment()
        if not ready:
            ready = auto_install_missing_tools()
        if ready and python_ready:
            print_colored(f"Network Analyzer v{VERSION} is ready.", "green", bold=True)
            if sys.stdin.isatty():
                print_colored("\nSelect the wireless interface to use for this session.", "cyan")
                core.select_interface_interactive()
            return 0
        print_colored("Readiness check is incomplete; install the items above and re-run.", "yellow")
        return 1

    if args.doctor:
        import json
        report = core.environment_report()
        print(json.dumps(report, indent=2))
        return 0 if not report['missing_tools'] and not report['missing_python_packages'] else 1

    if args.dev_automate:
        return 0 if DevAutomate(core).run() else 1

    if args.get_interfaces:
        for iface in core.detect_interfaces():
            print(iface)
        return 0

    if args.get_active_interface:
        print(core.active_interface if core.active_interface else "none")
        return 0

    if args.select_interface:
        core.select_interface_interactive()
        return 0

    if args.show_layout:
        tm = TerminalManager()
        tm.show_layout()
        return 0

    if args.enable_monitor is not None:
        interface = args.enable_monitor or core.active_interface
        me = MonitorEngine(core)
        return 0 if me.enable_monitor_mode(interface, visual=args.visual) else 1

    if args.disable_monitor:
        me = MonitorEngine(core)
        return 0 if me.disable_monitor_mode(visual=args.visual) else 1

    if args.scan:
        if args.multi_terminal:
            enhanced = EnhancedMonitor(core)
            return 0 if enhanced.run_discovery_workflow() else 1
        else:
            de = DiscoveryEngine(core)
            if not de.ensure_prerequisites():
                return 1
            csv_file = de.scan_networks(visual=args.visual)
            if csv_file:
                networks = de.parse_scan_results(csv_file)
                de.display_networks(networks)
                de.save_json_results(csv_file, networks)
            de.monitor.prompt_restore_normal_mode(core.active_interface)
            return 0 if csv_file else 1

    if args.deauth:
        de = DeauthEngine(core)
        return 0 if de.interactive_deauth() else 1

    if args.handshake:
        he = HandshakeEngine(core)
        if not he.ensure_prerequisites():
            return 1
        return 0 if he.interactive_capture() else 1

    if args.crack:
        ce = CrackEngine(core)
        ce.interactive_crack()
        return 0

    if args.vuln:
        de = DiscoveryEngine(core)
        if not de.ensure_prerequisites():
            return 1
        csv_file = de.scan_networks(visual=args.visual)
        if csv_file:
            networks = de.parse_scan_results(csv_file)
            from engines.vulnerability import assess_networks
            assessed = assess_networks(networks)
            de.display_networks(assessed)
            de.save_json_results(csv_file, assessed)
        de.monitor.prompt_restore_normal_mode(core.active_interface)
        return 0 if csv_file else 1

    if args.enhanced_monitor:
        enhanced = EnhancedMonitor(core)
        return 0 if enhanced.run() else 1

    if args.wifi_clients:
        if not core.ensure_root():
            return 1
        monitor = MonitorEngine(core)
        interface = monitor.ensure_monitor_mode(
            core.active_interface,
            prompt=True,
            visual=True,
        )
        if not interface:
            return 1
        if not core.ensure_root():
            return 1
        command = core.privileged_command(
            build_monitor_command(interface, output_path=args.wifi_client_output)
        )
        terminal = TerminalManager()
        result = terminal.run_live_command(
            f"Wi-Fi Clients - {interface}",
            command,
            geometry="122x42",
            interrupt_ok=True,
        )
        return 0 if result == 0 else 1

    if args.monitor:
        if not core.ensure_root():
            return 1
        interface = MonitorEngine(core).ensure_monitor_mode(core.active_interface)
        if not interface:
            return 1
        tm = TerminalManager()
        return 0 if tm.create_multi_terminal_layout(
            "monitor", interface=interface
        ) else 1

    if args.ai_anomaly:
        ai = AIAnomalyEngine(core)
        try:
            return 0 if ai.run_live_monitoring() else 1
        finally:
            ai.store.close()

    if args.ai_menu:
        ai_anomaly_menu(core)
        return 0

    if args.analyze:
        from engines.analysis import load_and_summarize
        scan_dir = Path(core.config.get('output_dirs', {}).get('scans', './scans'))
        json_files = list(scan_dir.glob("*.json"))
        if not json_files:
            print_colored("No saved scan data found.", "yellow")
            return 0
        print_colored("Available scan files:", "cyan")
        for i, f in enumerate(json_files):
            print_colored(f"  [{i}] {f.name}", "white")
        choice = input_colored("Select file index: ", "green")
        try:
            idx = int(choice)
            if 0 <= idx < len(json_files):
                summary = load_and_summarize(str(json_files[idx]))
                if summary.get('error'):
                    print_colored(summary['error'], "red")
                    return 1
                import json
                print(json.dumps(summary, indent=2))
            else:
                print_colored("Invalid index.", "red")
                return 1
        except (OSError, ValueError, TypeError) as exc:
            print_colored("Invalid input.", "red")
            return 1
        return 0

    if args.export:
        from engines.analysis import export_markdown_report
        scan_dir = Path(core.config.get('output_dirs', {}).get('scans', './scans'))
        files = sorted(scan_dir.glob('*.json'))
        if not files:
            print_colored("No saved scan data found.", "yellow")
            return 0
        for index, file in enumerate(files):
            print_colored(f"  [{index}] {file.name}", "white")
        try:
            selected = int(input_colored("Select scan file index: ", "green"))
            if not 0 <= selected < len(files):
                raise IndexError
            report = export_markdown_report(files[selected], Path(core.config.get('output_dirs', {}).get('reports', './reports')))
            print_colored(f"Report exported: {report}", "green", bold=True)
        except (OSError, ValueError, IndexError, TypeError):
            print_colored("Invalid selection.", "red")
            return 1
        return 0

    if args.sysinfo:
        print_colored("\nSystem Information", "cyan", bold=True)
        print_colored("═" * 50, "cyan")
        import platform
        print_colored(f"OS: {platform.system()} {platform.release()}", "white")
        print_colored(f"Python: {platform.python_version()}", "white")
        print_colored(f"Active interface: {core.active_interface or 'None'}", "white")
        print_colored("═" * 50, "cyan")
        return 0

    parser.print_help()
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main() )
    except KeyboardInterrupt:
        cleanup()
        sys.exit(0)
