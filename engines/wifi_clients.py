#!/usr/bin/env python3
"""Passive Wi-Fi access-point/client monitor powered by Scapy."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


BROADCAST = "ff:ff:ff:ff:ff:ff"
HIDDEN_SSID = "<hidden>"
UNKNOWN_SSID = "<unknown>"

Dot11 = None
Dot11Beacon = None
Dot11Elt = None
RadioTap = None
sniff = None


@dataclass
class ClientInfo:
    mac: str
    packets: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    bytes_total: int = 0
    last_signal: Optional[int] = None
    last_rate: Optional[float] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def direction(self) -> str:
        if self.tx_packets and self.rx_packets:
            return "both"
        if self.tx_packets:
            return "client->ap"
        if self.rx_packets:
            return "ap->client"
        return "-"


@dataclass
class NetworkInfo:
    bssid: str
    ssid: str = HIDDEN_SSID
    channel: Optional[int] = None
    signal: Optional[int] = None
    clients: Set[str] = field(default_factory=set)
    client_details: Dict[str, ClientInfo] = field(default_factory=dict)
    beacons: int = 0
    data_packets: int = 0
    bytes_total: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


def _load_scapy() -> bool:
    """Import Scapy lazily so the main application can start without it."""
    global Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff
    if sniff is not None:
        return True
    try:
        from scapy.all import (  # type: ignore
            Dot11 as scapy_dot11,
            Dot11Beacon as scapy_dot11_beacon,
            Dot11Elt as scapy_dot11_elt,
            RadioTap as scapy_radiotap,
            sniff as scapy_sniff,
        )
    except ImportError:
        return False
    Dot11 = scapy_dot11
    Dot11Beacon = scapy_dot11_beacon
    Dot11Elt = scapy_dot11_elt
    RadioTap = scapy_radiotap
    sniff = scapy_sniff
    return True


def build_monitor_command(
    interface: str,
    *,
    refresh_interval: float = 2.0,
    fixed_channel: Optional[int] = None,
    hop_interval: float = 0.5,
    output_path: Optional[Path] = None,
    save_interval: float = 5.0,
    target_bssid: Optional[str] = None,
    target_ssid: Optional[str] = None,
    initial_channel: Optional[int] = None,
    initial_signal: Optional[int] = None,
    channel_control: bool = True,
    known_clients: Optional[List[str]] = None,
) -> List[str]:
    """Return the module command used by menu and CLI launchers."""
    command = [
        sys.executable,
        "-m",
        "engines.wifi_clients",
        interface,
        "--refresh",
        f"{refresh_interval:g}",
        "--hop-interval",
        f"{hop_interval:g}",
    ]
    if fixed_channel is not None:
        command.extend(["--fixed-channel", str(fixed_channel)])
    if target_bssid:
        command.extend(["--bssid", target_bssid])
    if target_ssid:
        command.extend(["--ssid", target_ssid])
    if initial_channel is not None:
        command.extend(["--initial-channel", str(initial_channel)])
    if initial_signal is not None:
        command.extend(["--initial-signal", str(initial_signal)])
    if not channel_control:
        command.append("--no-channel-control")
    for client in known_clients or []:
        command.extend(["--known-client", client])
    if output_path is not None:
        command.extend([
            "--output",
            str(output_path),
            "--save-interval",
            f"{save_interval:g}",
        ])
    return command


class PassiveWiFiClientMonitor:
    """Passive monitor that maps observed Wi-Fi stations to access points."""

    def __init__(
        self,
        interface: str,
        refresh_interval: float = 2.0,
        channel_hop: bool = True,
        hop_interval: float = 0.5,
        output_path: Optional[Path] = None,
        save_interval: float = 5.0,
        target_bssid: Optional[str] = None,
        target_ssid: Optional[str] = None,
        initial_channel: Optional[int] = None,
        initial_signal: Optional[int] = None,
        channel_control: bool = True,
        known_clients: Optional[List[str]] = None,
    ):
        self.interface = interface
        self.refresh_interval = max(0.5, float(refresh_interval))
        self.channel_hop = channel_hop
        self.hop_interval = max(0.1, float(hop_interval))
        self.networks: Dict[str, NetworkInfo] = {}
        self.running = False
        self.lock = threading.Lock()
        self.started_at = time.time()
        self.current_channel: Optional[int] = None
        self.recent_frames: Dict[Tuple[str, str, str, str, str, int, int], float] = {}
        self.frame_cache_ttl = 3.0
        self.output_path = Path(output_path) if output_path else None
        self.save_interval = max(1.0, float(save_interval))
        self.last_saved_at = 0.0
        self.target_bssid = self.normalize_mac(target_bssid)
        self.target_ssid = target_ssid
        self.channel_control = channel_control
        self.known_clients = {
            client for client in (self.normalize_mac(mac) for mac in known_clients or [])
            if client
        }
        if initial_channel is not None:
            self.current_channel = initial_channel
        self.channels = [
            1, 6, 11,
            2, 3, 4, 5, 7, 8, 9, 10,
            36, 40, 44, 48,
            52, 56, 60, 64,
            100, 104, 108, 112,
            116, 120, 124, 128,
            132, 136, 140,
            149, 153, 157, 161, 165,
        ]
        if self.target_bssid:
            self.networks[self.target_bssid] = NetworkInfo(
                bssid=self.target_bssid,
                ssid=target_ssid or UNKNOWN_SSID,
                channel=initial_channel,
                signal=initial_signal,
            )

    def _wanted_bssid(self, bssid: str) -> bool:
        return self.target_bssid is None or bssid == self.target_bssid

    def _client_status(self, mac: str) -> str:
        if not self.known_clients:
            return "observed"
        return "known" if mac in self.known_clients else "unknown"

    @staticmethod
    def normalize_mac(mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        normalized = mac.lower()
        if normalized == BROADCAST:
            return None
        try:
            first_octet = int(normalized.split(":")[0], 16)
        except (ValueError, IndexError):
            return None
        if first_octet & 1:
            return None
        return normalized

    @staticmethod
    def extract_ssid(packet: Any) -> str:
        if Dot11Elt is None:
            return HIDDEN_SSID
        try:
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    raw = bytes(elt.info)
                    if not raw:
                        return HIDDEN_SSID
                    return raw.decode("utf-8", errors="replace")
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return HIDDEN_SSID

    @staticmethod
    def extract_channel(packet: Any) -> Optional[int]:
        if Dot11Elt is None:
            return None
        try:
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3 and elt.info:
                    return int(bytes(elt.info)[0])
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return None

    @staticmethod
    def extract_signal(packet: Any) -> Optional[int]:
        if RadioTap is None:
            return None
        try:
            signal_value = getattr(packet[RadioTap], "dBm_AntSignal", None)
            if signal_value is not None:
                return int(signal_value)
        except Exception:
            pass
        return None

    @staticmethod
    def extract_rate(packet: Any) -> Optional[float]:
        if RadioTap is None:
            return None
        try:
            rate_value = getattr(packet[RadioTap], "Rate", None)
            if rate_value is None:
                return None
            rate = float(rate_value)
            return rate if rate > 0 else None
        except Exception:
            return None

    def handle_beacon(self, packet: Any) -> None:
        bssid = self.normalize_mac(packet.addr3)
        if not bssid or not self._wanted_bssid(bssid):
            return
        ssid = self.extract_ssid(packet)
        channel = self.extract_channel(packet)
        signal_level = self.extract_signal(packet)

        with self.lock:
            network = self.networks.get(bssid)
            if network is None:
                network = NetworkInfo(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    signal=signal_level,
                )
                self.networks[bssid] = network
                network.beacons += 1
                return
            network.beacons += 1
            if ssid != HIDDEN_SSID:
                network.ssid = ssid
            if channel is not None:
                network.channel = channel
            if signal_level is not None:
                network.signal = signal_level
            network.last_seen = time.time()

    def _frame_relationship(self, packet: Any) -> Optional[Tuple[str, str, str]]:
        dot11 = packet[Dot11]
        fc = int(dot11.FCfield)
        to_ds = bool(fc & 0x1)
        from_ds = bool(fc & 0x2)

        if to_ds and not from_ds:
            bssid = self.normalize_mac(dot11.addr1)
            client = self.normalize_mac(dot11.addr2)
            direction = "tx"
        elif from_ds and not to_ds:
            bssid = self.normalize_mac(dot11.addr2)
            client = self.normalize_mac(dot11.addr1)
            direction = "rx"
        else:
            return None

        if not bssid or not client or client == bssid or not self._wanted_bssid(bssid):
            return None
        return bssid, client, direction

    def handle_data_frame(self, packet: Any) -> None:
        relationship = self._frame_relationship(packet)
        if relationship is None:
            return
        bssid, client, direction = relationship
        try:
            packet_size = len(bytes(packet)) if hasattr(packet, "__bytes__") else len(packet)
        except Exception:
            packet_size = 0
        signal = self.extract_signal(packet)
        rate = self.extract_rate(packet)

        with self.lock:
            if self._is_duplicate_frame_locked(packet, bssid, client, direction):
                return
            network = self.networks.get(bssid)
            if network is None:
                network = NetworkInfo(bssid=bssid, ssid=UNKNOWN_SSID)
                self.networks[bssid] = network
            network.clients.add(client)
            network.data_packets += 1
            network.bytes_total += packet_size
            if direction == "rx" and signal is not None:
                network.signal = signal
            network.last_seen = time.time()
            detail = network.client_details.get(client)
            if detail is None:
                detail = ClientInfo(mac=client)
                network.client_details[client] = detail
            detail.packets += 1
            if direction == "tx":
                detail.tx_packets += 1
                if signal is not None:
                    detail.last_signal = signal
            else:
                detail.rx_packets += 1
            detail.bytes_total += packet_size
            if rate is not None:
                detail.last_rate = rate
            detail.last_seen = network.last_seen

    def _is_duplicate_frame_locked(
        self,
        packet: Any,
        bssid: str,
        client: str,
        direction: str,
    ) -> bool:
        """Suppress quick 802.11 retry frames so counters track fresh frames."""
        try:
            dot11 = packet[Dot11]
            fc = int(dot11.FCfield)
            sequence_control = int(getattr(dot11, "SC"))
        except Exception:
            return False

        now = time.time()
        stale_before = now - self.frame_cache_ttl
        for key, seen_at in list(self.recent_frames.items()):
            if seen_at < stale_before:
                del self.recent_frames[key]

        transmitter = self.normalize_mac(getattr(dot11, "addr2", None)) or "-"
        receiver = self.normalize_mac(getattr(dot11, "addr1", None)) or "-"
        sequence = sequence_control >> 4
        fragment = sequence_control & 0xF
        key = (bssid, client, direction, transmitter, receiver, sequence, fragment)
        last_seen = self.recent_frames.get(key)
        self.recent_frames[key] = now

        retry_frame = bool(fc & 0x8)
        return last_seen is not None and (retry_frame or now - last_seen < 0.25)

    def packet_handler(self, packet: Any) -> None:
        if Dot11 is None or Dot11Beacon is None:
            return
        if not packet.haslayer(Dot11):
            return
        if packet.haslayer(Dot11Beacon):
            self.handle_beacon(packet)
        elif packet[Dot11].type == 2:
            self.handle_data_frame(packet)

    @staticmethod
    def _privileged_command(command: List[str]) -> List[str]:
        if os.geteuid() == 0:
            return command
        return ["sudo", "-n", *command]

    def set_channel(self, channel: int) -> bool:
        try:
            result = subprocess.run(
                self._privileged_command([
                    "iw",
                    "dev",
                    self.interface,
                    "set",
                    "channel",
                    str(channel),
                ]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            return False
        if result.returncode == 0:
            self.current_channel = channel
            return True
        return False

    def channel_hopper(self) -> None:
        while self.running:
            for channel in self.channels:
                if not self.running:
                    break
                self.set_channel(channel)
                time.sleep(self.hop_interval)

    @staticmethod
    def _style(text: str, code: str) -> str:
        if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
            return text
        return f"\033[{code}m{text}\033[0m"

    @staticmethod
    def _short_age(timestamp: float) -> str:
        age = max(0, int(time.time() - timestamp))
        if age < 2:
            return "now"
        if age < 60:
            return f"{age}s"
        minutes, seconds = divmod(age, 60)
        if minutes < 60:
            return f"{minutes}m{seconds:02d}s"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h{minutes:02d}m"

    @staticmethod
    def _signal_bar(signal: Optional[int]) -> str:
        if signal is None:
            return "-----"
        if signal >= -50:
            return "|||||"
        if signal >= -60:
            return "||||."
        if signal >= -70:
            return "|||.."
        if signal >= -80:
            return "||..."
        return "|...."

    @staticmethod
    def _human_bytes(value: int) -> str:
        amount = float(max(0, value))
        units = ("B", "KB", "MB", "GB")
        for unit in units:
            if amount < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(amount)}B"
                return f"{amount:.1f}{unit}"
            amount /= 1024
        return f"{int(amount)}B"

    @staticmethod
    def _packet_rate(client: ClientInfo) -> float:
        span = max(1.0, time.time() - client.first_seen)
        return client.packets / span

    @staticmethod
    def _clip(value: Any, width: int) -> str:
        text = str(value)
        if len(text) <= width:
            return text
        return text[: max(0, width - 1)] + "."

    def _snapshot(self) -> Tuple[List[NetworkInfo], int]:
        with self.lock:
            source_networks = self.networks.values()
            if self.target_bssid:
                target = self.networks.get(self.target_bssid)
                source_networks = [target] if target else []
            networks = sorted(
                source_networks,
                key=lambda network: (
                    len(network.clients),
                    network.signal if network.signal is not None else -999,
                    network.last_seen,
                ),
                reverse=True,
            )
            copies = [
                NetworkInfo(
                    bssid=network.bssid,
                    ssid=network.ssid,
                    channel=network.channel,
                    signal=network.signal,
                    clients=set(network.clients),
                    client_details={
                        mac: ClientInfo(
                            mac=detail.mac,
                            packets=detail.packets,
                            tx_packets=detail.tx_packets,
                            rx_packets=detail.rx_packets,
                            bytes_total=detail.bytes_total,
                            last_signal=detail.last_signal,
                            last_rate=detail.last_rate,
                            first_seen=detail.first_seen,
                            last_seen=detail.last_seen,
                        )
                        for mac, detail in network.client_details.items()
                    },
                    beacons=network.beacons,
                    data_packets=network.data_packets,
                    bytes_total=network.bytes_total,
                    first_seen=network.first_seen,
                    last_seen=network.last_seen,
                )
                for network in networks
            ]
        total_clients = sum(len(network.clients) for network in copies)
        return copies, total_clients

    def snapshot_document(self) -> Dict[str, Any]:
        networks, total_clients = self._snapshot()
        captured_at = datetime.now().astimezone().isoformat(timespec="seconds")
        return {
            "interface": self.interface,
            "captured_at": captured_at,
            "uptime_seconds": int(time.time() - self.started_at),
            "channel_hop": self.channel_hop,
            "channel_control": self.channel_control,
            "target_bssid": self.target_bssid,
            "known_clients": sorted(self.known_clients),
            "current_channel": self.current_channel,
            "network_count": len(networks),
            "observed_client_associations": total_clients,
            "networks": [
                {
                    "ssid": network.ssid,
                    "bssid": network.bssid,
                    "channel": network.channel,
                    "signal": network.signal,
                    "client_count": len(network.clients),
                    "beacons": network.beacons,
                    "data_packets": network.data_packets,
                    "bytes_total": network.bytes_total,
                    "clients": [
                        {
                            "mac": detail.mac,
                            "packets": detail.packets,
                            "tx_packets": detail.tx_packets,
                            "rx_packets": detail.rx_packets,
                            "bytes_total": detail.bytes_total,
                            "last_signal": detail.last_signal,
                            "last_rate": detail.last_rate,
                            "direction": detail.direction,
                            "status": self._client_status(detail.mac),
                            "first_seen": datetime.fromtimestamp(
                                detail.first_seen
                            ).astimezone().isoformat(timespec="seconds"),
                            "last_seen": datetime.fromtimestamp(
                                detail.last_seen
                            ).astimezone().isoformat(timespec="seconds"),
                        }
                        for detail in sorted(
                            network.client_details.values(),
                            key=lambda item: (item.packets, item.last_seen),
                            reverse=True,
                        )
                    ],
                    "first_seen": datetime.fromtimestamp(
                        network.first_seen
                    ).astimezone().isoformat(timespec="seconds"),
                    "last_seen": datetime.fromtimestamp(
                        network.last_seen
                    ).astimezone().isoformat(timespec="seconds"),
                }
                for network in networks
            ],
        }

    def save_snapshot(self) -> bool:
        if self.output_path is None:
            return True
        temporary = self.output_path.with_suffix(self.output_path.suffix + ".tmp")
        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(
                json.dumps(self.snapshot_document(), indent=2),
                encoding="utf-8",
            )
            temporary.replace(self.output_path)
            self.last_saved_at = time.time()
            return True
        except OSError as exc:
            print(f"\nUnable to save client monitor log: {exc}")
            return False

    def save_snapshot_if_due(self) -> None:
        if self.output_path is None:
            return
        if time.time() - self.last_saved_at >= self.save_interval:
            self.save_snapshot()

    def render_snapshot(self) -> str:
        terminal_size = shutil.get_terminal_size((112, 32))
        width = max(96, min(132, terminal_size.columns))
        height = max(18, terminal_size.lines)
        ssid_width = max(18, min(34, width - 80))
        networks, total_clients = self._snapshot()
        if self.target_bssid:
            network = networks[0] if networks else NetworkInfo(
                bssid=self.target_bssid,
                ssid=self.target_ssid or UNKNOWN_SSID,
                channel=self.current_channel,
            )
            return self.render_target_snapshot(network, width, height)
        elapsed = int(time.time() - self.started_at)
        elapsed_text = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        if not self.channel_control:
            mode = "external channel control"
        elif self.channel_hop:
            mode = f"hopping ch {self.current_channel or '-'}"
        else:
            mode = f"fixed channel {self.current_channel or '-'}"
        rule = "-" * width
        title = "Passive Wi-Fi Client Monitor"
        if self.target_bssid:
            title = f"AP Client Monitor {self.target_bssid}"
        header = (
            f"{title:<36} iface {self.interface:<14} {mode:<18} uptime {elapsed_text}"
        )
        lines = [
            self._style(header[:width], "1;36"),
            self._style(rule, "36"),
            (
                f"{'SSID':<{ssid_width}}  {'BSSID':<17}  {'CH':>3}  "
                f"{'RSSI':>8}  {'LEVEL':<5}  {'UNIQUE':>7}  {'LAST':>7}"
            ),
            rule,
        ]
        if not networks:
            lines.extend([
                "",
                "Listening for beacons and associated client traffic...",
                "Stay on one channel longer if you know the target channel.",
                "",
            ])
        max_body_rows = max(4, height - 9 - (1 if self.output_path else 0))
        body_rows = 0
        hidden_networks = 0
        hidden_clients = 0
        for network in networks:
            if body_rows >= max_body_rows:
                hidden_networks += 1
                hidden_clients += len(network.clients)
                continue
            signal = f"{network.signal} dBm" if network.signal is not None else "-"
            channel = str(network.channel) if network.channel is not None else "-"
            lines.append(
                f"{self._clip(network.ssid, ssid_width):<{ssid_width}}  "
                f"{network.bssid:<17}  "
                f"{channel:>3}  "
                f"{signal:>8}  "
                f"{self._signal_bar(network.signal):<5}  "
                f"{len(network.clients):>7}  "
                f"{self._short_age(network.last_seen):>7}"
            )
            body_rows += 1
            for number, client in enumerate(sorted(network.clients), start=1):
                if body_rows >= max_body_rows:
                    hidden_clients += len(network.clients) - number + 1
                    break
                lines.append(
                    f"  {'Client ' + str(number):<{ssid_width - 2}}  "
                    f"{client:<17}  {'':>3}  {'':>8}  {'':<5}  {'':>7}  {'':>7}"
                )
                body_rows += 1
            if body_rows < max_body_rows:
                lines.append("")
                body_rows += 1
        if hidden_networks or hidden_clients:
            lines.append(
                f"... {hidden_networks} network(s), {hidden_clients} client(s) hidden "
                "to keep the live view stable"
            )
        footer = (
            f"Networks: {len(networks)}   "
            f"Unique client associations: {total_clients}   "
            f"Updated: {datetime.now().strftime('%H:%M:%S')}   "
            "Ctrl+C stops"
        )
        lines.extend([self._style(rule, "36"), self._style(footer[:width], "1;32")])
        if self.output_path is not None:
            lines.append(f"Saving JSON log: {self.output_path}")
        return "\n".join(lines)

    def render_target_snapshot(self, network: NetworkInfo, width: int, height: int) -> str:
        rule = "-" * width
        elapsed = int(time.time() - self.started_at)
        elapsed_text = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        signal = f"{network.signal} dBm" if network.signal is not None else "-"
        channel = str(network.channel) if network.channel is not None else "-"
        mode = f"channel {channel}" if self.channel_control else "external channel control"
        clients = sorted(
            network.client_details.values(),
            key=lambda item: (item.first_seen, item.mac),
        )
        max_rows = max(3, height - 12)
        visible_clients = clients[:max_rows]
        hidden_count = max(0, len(clients) - len(visible_clients))
        lines = [
            self._style(f"AP Client Monitor - {network.ssid}", "1;36"),
            self._style(rule, "36"),
            f"BSSID: {network.bssid}   CH: {channel}   RSSI: {signal}   "
            f"LEVEL: {self._signal_bar(network.signal)}   MODE: {mode}   UPTIME: {elapsed_text}",
            f"Beacons: {network.beacons}   Data frames: {network.data_packets}   "
            f"Bytes: {self._human_bytes(network.bytes_total)}   "
            f"Unique clients: {len(clients)}",
            rule,
            (
                f"{'#':<3} {'CLIENT MAC':<17} {'STATUS':<8} {'PWR':>6} {'RATE':>8} "
                f"{'FRAMES':>7} {'FPS':>7} {'BYTES':>9} {'DIR':<10} {'LAST':>7}"
            ),
            rule,
        ]
        if not clients:
            lines.extend([
                "",
                "No associated client traffic observed for this AP yet.",
                "Keep the adapter on the AP channel and wait for data frames.",
                "",
            ])
        for index, client in enumerate(visible_clients, start=1):
            client_signal = f"{client.last_signal}" if client.last_signal is not None else "-"
            rate = f"{client.last_rate:g}" if client.last_rate is not None else "-"
            lines.append(
                f"{index:<3} {client.mac:<17} {self._client_status(client.mac):<8} "
                f"{client_signal:>6} {rate:>8} "
                f"{client.packets:>7} {self._packet_rate(client):>7.1f} "
                f"{self._human_bytes(client.bytes_total):>9} "
                f"{client.direction:<10} {self._short_age(client.last_seen):>7}"
            )
        if hidden_count:
            lines.append(f"... {hidden_count} more client(s) hidden to keep the live view stable")
        footer = (
            f"Updated: {datetime.now().strftime('%H:%M:%S')}   "
            f"Unique client associations: {len(clients)}   Ctrl+C stops"
        )
        lines.extend([rule, self._style(footer[:width], "1;32")])
        if self.output_path is not None:
            lines.append(f"Saving JSON log: {self.output_path}")
        return "\n".join(lines)

    def display(self) -> None:
        while self.running:
            print("\033[2J\033[H", end="")
            print(self.render_snapshot(), flush=True)
            self.save_snapshot_if_due()
            time.sleep(self.refresh_interval)

    def start(self) -> int:
        if not _load_scapy():
            print("Scapy is required for the passive client monitor.")
            print("Install it with: python -m pip install scapy")
            return 1

        self.running = True
        self.started_at = time.time()
        hopper = None
        if self.channel_hop and self.channel_control:
            hopper = threading.Thread(target=self.channel_hopper, daemon=True)
            hopper.start()
        display_thread = threading.Thread(target=self.display, daemon=True)
        display_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda _packet: not self.running,
            )
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("\nPermission denied. Run with sudo or authorize sudo from Network Analyzer.")
            return 1
        except OSError as exc:
            print(f"\nUnable to sniff on {self.interface}: {exc}")
            return 1
        finally:
            self.running = False
            if hopper and hopper.is_alive():
                hopper.join(timeout=1)
            if self.output_path is not None and self.save_snapshot():
                print(f"\nSaved client monitor log: {self.output_path}")
            print("\nMonitoring stopped.")
        return 0

    def stop(self) -> None:
        self.running = False


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Passive Wi-Fi AP/client discovery monitor")
    parser.add_argument("interface", help="Wireless interface in monitor mode, e.g. wlan0mon")
    parser.add_argument(
        "--fixed-channel",
        type=int,
        help="Monitor only one Wi-Fi channel instead of hopping between channels",
    )
    parser.add_argument("--refresh", type=float, default=2.0, help="Display refresh interval")
    parser.add_argument("--hop-interval", type=float, default=0.5, help="Channel hop interval")
    parser.add_argument("--output", type=Path, help="Save observed AP/client data as JSON")
    parser.add_argument("--save-interval", type=float, default=5.0, help="JSON save interval")
    parser.add_argument("--bssid", help="Only show one access point and its clients")
    parser.add_argument("--ssid", help="Display name to use before the first beacon is observed")
    parser.add_argument("--initial-channel", type=int, help="Channel from the initial discovery scan")
    parser.add_argument("--initial-signal", type=int, help="Signal from the initial discovery scan")
    parser.add_argument(
        "--no-channel-control",
        action="store_true",
        help="Do not tune or hop channels; another monitor controls the adapter",
    )
    parser.add_argument(
        "--known-client",
        action="append",
        default=[],
        help="Authorized client MAC; repeat for multiple known clients",
    )
    args = parser.parse_args(argv)

    monitor = PassiveWiFiClientMonitor(
        interface=args.interface,
        refresh_interval=args.refresh,
        channel_hop=args.fixed_channel is None,
        hop_interval=args.hop_interval,
        output_path=args.output,
        save_interval=args.save_interval,
        target_bssid=args.bssid,
        target_ssid=args.ssid,
        initial_channel=args.initial_channel,
        initial_signal=args.initial_signal,
        channel_control=not args.no_channel_control,
        known_clients=args.known_client,
    )
    if (
        args.fixed_channel is not None
        and not args.no_channel_control
        and not monitor.set_channel(args.fixed_channel)
    ):
        print(f"Warning: could not set channel {args.fixed_channel}")

    def shutdown_handler(_signum: int, _frame: Any) -> None:
        monitor.stop()

    signal.signal(signal.SIGTERM, shutdown_handler)
    return monitor.start()


if __name__ == "__main__":
    sys.exit(main())
