#!/usr/bin/env python3
"""Passive, explainable wireless anomaly detection and pattern learning."""

import json
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np

try:
    import joblib
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    joblib = None
    IsolationForest = None
    ML_AVAILABLE = False

from .anomaly_store import AnomalyStore
from .core import NetworkAnalyzerCore
from .utils import PROJECT_ROOT, print_colored


FEATURE_SCHEMA = (
    "network_count", "average_signal", "security_type_count", "channel_count",
    "open_count", "wep_count", "wpa_count", "wpa2_count", "wpa3_count",
    "unknown_count", "hidden_count",
)
SECURITY_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
MODEL_FORMAT_VERSION = 2
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class AIAnomalyEngine:
    """Learn normal radio patterns and report explainable deviations."""

    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core
        config = self.core.config.get("ai", {})
        configured_db = config.get("patterns_db", "./data/anomaly_patterns.db")
        db_path = Path(configured_db)
        if not db_path.is_absolute():
            db_path = (PROJECT_ROOT / db_path).resolve()
        # Older versions used JSON. Preserve that file and migrate it once,
        # including installations that have moved to the new default path.
        self.legacy_json_path = db_path if db_path.suffix.lower() == ".json" else None
        if self.legacy_json_path:
            db_path = db_path.with_suffix(".db")
        else:
            default_legacy = PROJECT_ROOT / "ai_patterns.json"
            self.legacy_json_path = default_legacy if default_legacy.exists() else None
        self.db_path = db_path
        self.model_path = Path(config.get("model_path", "./models/anomaly_model.joblib"))
        if not self.model_path.is_absolute():
            self.model_path = (PROJECT_ROOT / self.model_path).resolve()
        self.store = AnomalyStore(self.db_path)
        self.model = self._load_model()
        self.baseline = self.store.get_metadata("baseline")
        self.running = False
        self._migrate_legacy_json()

    @property
    def pattern_db(self) -> Dict[str, Any]:
        """Compatibility summary for callers from the previous JSON version."""
        return {
            "baseline": self.baseline,
            "model_trained": self.model is not None,
            "history": self.store.training_snapshots(limit=100),
            "stats": self.store.stats(),
        }

    def _migrate_legacy_json(self) -> None:
        if not self.legacy_json_path or not self.legacy_json_path.exists():
            return
        if self.store.get_metadata("legacy_json_migrated", False):
            return
        try:
            document = json.loads(self.legacy_json_path.read_text(encoding="utf-8"))
            for snapshot in document.get("history", []):
                normalized = self._normalize_snapshot(snapshot)
                self.store.add_snapshot(normalized, source="legacy-json")
                self.store.learn_networks(normalized["networks"])
            if document.get("baseline") and not self.baseline:
                self.baseline = document["baseline"]
                self.store.set_metadata("baseline", self.baseline)
            self.store.set_metadata("legacy_json_migrated", True)
        except (OSError, ValueError, TypeError) as exc:
            print_colored(f"Legacy AI data was not migrated: {exc}", "yellow")

    def _load_model(self):
        if not ML_AVAILABLE or not self.model_path.exists():
            return None
        try:
            payload = joblib.load(self.model_path)
            if not isinstance(payload, dict) or payload.get("format_version") != MODEL_FORMAT_VERSION:
                print_colored("Saved AI model uses old training features; import scans to retrain.", "yellow")
                return None
            if tuple(payload.get("feature_schema", ())) != FEATURE_SCHEMA:
                return None
            return payload.get("model")
        except Exception:
            print_colored("Saved AI model is incompatible; retraining is required.", "yellow")
        return None

    def ensure_prerequisites(self) -> bool:
        from .monitor import MonitorEngine
        if not shutil.which('airodump-ng'):
            print_colored("airodump-ng is required for live anomaly detection.", "red")
            return False
        if not self.core.ensure_root():
            return False
        return MonitorEngine(self.core).ensure_monitor_mode(
            self.core.active_interface
        ) is not None

    @staticmethod
    def _number(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _security(network: Dict[str, Any]) -> str:
        value = str(network.get("encryption_type") or network.get("encryption") or "Unknown")
        upper = value.upper()
        for name in ("WPA3", "WPA2", "WPA", "WEP"):
            if name in upper:
                return name
        return "Open" if upper in ("OPEN", "OPN", "") else "Unknown"

    def _capture_snapshot(self, duration: int = 10) -> Optional[Dict[str, Any]]:
        from .discovery import DiscoveryEngine
        from .monitor import MonitorEngine

        interface = MonitorEngine(self.core).ensure_monitor_mode(
            self.core.active_interface,
            prompt=False,
            allow_reselect=False,
        )
        if not interface:
            return None

        with tempfile.TemporaryDirectory(prefix="network_analyzer_ai_") as directory:
            prefix = Path(directory) / "snapshot"
            command = self.core.privileged_command([
                "airodump-ng", "--output-format", "csv", "-w", str(prefix),
                interface,
            ])
            process = None
            capture_failed = False
            try:
                process = subprocess.Popen(
                    command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                started = time.monotonic()
                while process.poll() is None and time.monotonic() - started < duration:
                    time.sleep(min(0.5, duration))
            except (OSError, subprocess.SubprocessError) as exc:
                print_colored(f"Snapshot capture failed: {exc}", "red")
                capture_failed = True
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            csv_path = prefix.with_name(prefix.name + "-01.csv")
            if capture_failed or not csv_path.exists():
                return None
            networks = DiscoveryEngine(self.core).parse_scan_results(csv_path)
        return self.snapshot_from_networks(networks)

    def snapshot_from_networks(
        self, networks: Iterable[Dict[str, Any]], timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        unique = {}
        for item in networks:
            network = dict(item)
            bssid = str(network.get("bssid", "")).strip().upper()
            if not bssid:
                continue
            network["bssid"] = bssid
            network["encryption_type"] = self._security(network)
            unique[bssid] = network
        values = list(unique.values())
        encryption = defaultdict(int)
        channels = defaultdict(int)
        signals = []
        for network in values:
            encryption[network["encryption_type"]] += 1
            channel = str(network.get("channel", "")).strip()
            if channel:
                channels[channel] += 1
            signal = self._number(network.get("signal"), default=float("nan"))
            if not np.isnan(signal):
                signals.append(signal)
        return {
            "timestamp": timestamp or time.time(),
            "networks": values,
            "count": len(values),
            "encryption_dist": dict(encryption),
            "channel_dist": dict(channels),
            "signal_avg": float(np.mean(signals)) if signals else 0.0,
        }

    def _normalize_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        if snapshot.get("networks"):
            return self.snapshot_from_networks(
                snapshot["networks"], self._number(snapshot.get("timestamp"), time.time())
            )
        return {
            "timestamp": self._number(snapshot.get("timestamp"), time.time()),
            "networks": [],
            "count": int(self._number(snapshot.get("count"))),
            "encryption_dist": dict(snapshot.get("encryption_dist", {})),
            "channel_dist": dict(snapshot.get("channel_dist", {})),
            "signal_avg": self._number(snapshot.get("signal_avg")),
        }

    def _extract_features(self, snapshot: Dict[str, Any]) -> np.ndarray:
        encryption = {str(k).upper(): self._number(v) for k, v in snapshot["encryption_dist"].items()}
        hidden = sum(
            1 for network in snapshot.get("networks", [])
            if str(network.get("essid") or "Hidden").strip().lower() == "hidden"
        )
        return np.asarray([
            self._number(snapshot.get("count")), self._number(snapshot.get("signal_avg")),
            len(encryption), len(snapshot.get("channel_dist", {})),
            encryption.get("OPEN", 0) + encryption.get("OPN", 0), encryption.get("WEP", 0),
            encryption.get("WPA", 0), encryption.get("WPA2", 0), encryption.get("WPA3", 0),
            encryption.get("UNKNOWN", 0), hidden,
        ], dtype=float)

    def _train_model(self, snapshots: List[Dict[str, Any]]) -> bool:
        minimum = max(5, int(self.core.config.get("ai", {}).get("minimum_training_samples", 10)))
        snapshots = [self._normalize_snapshot(item) for item in snapshots]
        if not snapshots:
            print_colored("No valid snapshots were available for learning.", "yellow")
            return False
        self.baseline = self._compute_baseline(snapshots)
        self.store.set_metadata("baseline", self.baseline)
        if len(snapshots) < minimum:
            print_colored(
                f"Baseline updated from {len(snapshots)} snapshot(s); {minimum} are needed for ML training.",
                "yellow",
            )
            return False
        if not ML_AVAILABLE:
            print_colored("Baseline saved; scikit-learn is unavailable for ML training.", "yellow")
            return False
        contamination = float(self.core.config.get("ai", {}).get("contamination", 0.08))
        contamination = min(0.5, max(0.001, contamination))
        model = IsolationForest(
            n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1
        )
        model.fit(np.vstack([self._extract_features(item) for item in snapshots]))
        self.model = model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "feature_schema": FEATURE_SCHEMA,
                     "format_version": MODEL_FORMAT_VERSION}, self.model_path)
        self.store.set_metadata("model_trained_at", time.time())
        print_colored(f"AI model trained with {len(snapshots)} snapshots.", "green")
        return True

    def _ml_result(self, snapshot: Dict[str, Any]) -> Tuple[Optional[float], List[Dict[str, str]]]:
        if self.model is None:
            return None, []
        features = self._extract_features(snapshot).reshape(1, -1)
        score = float(self.model.decision_function(features)[0])
        if int(self.model.predict(features)[0]) == -1:
            return score, [{
                "rule": "ml_outlier", "severity": "medium", "entity": "snapshot",
                "message": f"The combined radio pattern is unusual (model score {score:.3f}).",
            }]
        return score, []

    def _pattern_incidents(self, snapshot: Dict[str, Any]) -> List[Dict[str, str]]:
        incidents = []
        signal_delta = float(self.core.config.get("ai", {}).get("signal_surge_db", 18))
        channel_changes = bool(self.core.config.get("ai", {}).get("alert_channel_changes", True))
        for network in snapshot.get("networks", []):
            bssid = network["bssid"]
            essid = str(network.get("essid") or "Hidden").strip()
            security = self._security(network)
            channel = str(network.get("channel", "")).strip()
            signal = self._number(network.get("signal"), float("nan"))
            known = self.store.get_pattern(bssid)
            same_name = self.store.patterns_for_essid(essid) if essid.lower() != "hidden" else []
            trusted_same_name = [item for item in same_name if item["trusted"]]

            def add(rule: str, severity: str, message: str) -> None:
                incidents.append({"rule": rule, "severity": severity, "entity": bssid, "message": message})

            if not known or (not known["trusted"] and trusted_same_name):
                if trusted_same_name:
                    expected = ", ".join(item["bssid"] for item in trusted_same_name[:3])
                    severity = "high" if any(item["security"] != security for item in trusted_same_name) else "medium"
                    add(
                        "possible_evil_twin", severity,
                        f"New BSSID {bssid} is advertising trusted SSID {essid!r}; expected {expected}.",
                    )
                elif security == "Open":
                    add("new_open_ap", "high", f"New open network {essid!r} observed at {bssid}.")
                elif same_name:
                    add("new_bssid_for_ssid", "low", f"New BSSID {bssid} is advertising known SSID {essid!r}.")
                else:
                    add("new_access_point", "low", f"Previously unseen access point {essid!r} ({bssid}).")
                continue

            if known["trusted"] and SECURITY_RANK.get(security.upper(), -1) < SECURITY_RANK.get(str(known["security"]).upper(), -1):
                add(
                    "encryption_downgrade", "critical",
                    f"Trusted AP {essid!r} changed security from {known['security']} to {security}.",
                )
            if known["trusted"] and essid != known["essid"]:
                add("identity_change", "high", f"Trusted BSSID {bssid} changed SSID from {known['essid']!r} to {essid!r}.")
            if channel_changes and known["trusted"] and channel and known["channel"] and channel != known["channel"]:
                add("channel_change", "low", f"Trusted AP {essid!r} moved from channel {known['channel']} to {channel}.")
            if known["signal_mean"] is not None and not np.isnan(signal) and signal - float(known["signal_mean"]) >= signal_delta:
                add(
                    "signal_surge", "medium",
                    f"Signal for {essid!r} increased by {signal - float(known['signal_mean']):.1f} dB.",
                )
        return incidents

    def _statistical_incidents(self, snapshot: Dict[str, Any]) -> List[Dict[str, str]]:
        if not self.baseline:
            return []
        incidents = []
        threshold = float(self.core.config.get("ai", {}).get("detection_threshold", 2.5))
        count_std = max(float(self.baseline.get("std_count", 0)), 1.0)
        count_z = abs(snapshot["count"] - float(self.baseline.get("avg_count", 0))) / count_std
        if count_z >= threshold:
            incidents.append({
                "rule": "network_count_drift", "severity": "medium", "entity": "snapshot",
                "message": f"Network count is {snapshot['count']} versus a {self.baseline['avg_count']:.1f} baseline (z={count_z:.2f}).",
            })
        baseline_signal = float(self.baseline.get("avg_signal", 0))
        signal_std = max(float(self.baseline.get("std_signal", 0)), 2.5)
        if snapshot["count"] and baseline_signal:
            signal_z = abs(snapshot["signal_avg"] - baseline_signal) / signal_std
            if signal_z >= threshold:
                incidents.append({
                    "rule": "signal_environment_drift", "severity": "low", "entity": "snapshot",
                    "message": f"Average signal shifted to {snapshot['signal_avg']:.1f} dBm (z={signal_z:.2f}).",
                })
        return incidents

    def analyze_snapshot(
        self, snapshot: Dict[str, Any], source: str = "live", learn: bool = True
    ) -> List[Dict[str, str]]:
        snapshot = self._normalize_snapshot(snapshot)
        pattern_incidents = self._pattern_incidents(snapshot)
        statistical_incidents = self._statistical_incidents(snapshot)
        score, ml_incidents = self._ml_result(snapshot)
        incidents = self._deduplicate(pattern_incidents + statistical_incidents + ml_incidents)
        snapshot_id = self.store.add_snapshot(
            snapshot, source=source, interface=self.core.active_interface,
            anomaly_score=score, is_anomaly=bool(incidents),
        )
        if incidents:
            cooldown = max(0, int(self.core.config.get("ai", {}).get("incident_cooldown_seconds", 300)))
            self.store.add_incidents(snapshot_id, incidents, cooldown_seconds=cooldown)
        if learn:
            suspicious = {item.get("entity") for item in incidents
                          if item["rule"] in ("possible_evil_twin", "signal_surge",
                                              "encryption_downgrade", "identity_change")}
            rate = float(self.core.config.get("ai", {}).get("learning_rate", 0.05))
            self.store.learn_networks(
                [network for network in snapshot["networks"]
                 if network["bssid"] not in suspicious],
                learning_rate=rate,
            )
        return incidents

    @staticmethod
    def _deduplicate(items: List[Dict[str, str]]) -> List[Dict[str, str]]:
        result, seen = [], set()
        for item in sorted(items, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True):
            key = (item["rule"], item.get("entity"), item["message"])
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def import_scan_files(self, files: Iterable[Path], train: bool = True) -> Dict[str, int]:
        imported = skipped = 0
        snapshots = []
        imported_sources = self.store.get_metadata("imported_scan_sources", {})
        if not isinstance(imported_sources, dict):
            imported_sources = {}
        for path in files:
            try:
                path = Path(path)
                stat = path.stat()
                source_key = str(path.resolve())
                signature = f"{stat.st_mtime_ns}:{stat.st_size}"
                if imported_sources.get(source_key) == signature:
                    skipped += 1
                    continue
                document = json.loads(path.read_text(encoding="utf-8"))
                networks = document.get("networks", []) if isinstance(document, dict) else document
                if not isinstance(networks, list):
                    raise ValueError("scan JSON must contain a network list")
                snapshot = self.snapshot_from_networks(networks, stat.st_mtime)
                self.store.add_snapshot(snapshot, source=f"import:{path.name}")
                self.store.learn_networks(snapshot["networks"])
                snapshots.append(snapshot)
                imported_sources[source_key] = signature
                imported += 1
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                skipped += 1
                print_colored(f"Skipped {Path(path).name}: {exc}", "yellow")
        if imported:
            self.store.set_metadata("imported_scan_sources", imported_sources)
        if train and (snapshots or self.model is None):
            self._train_model(self.store.training_snapshots())
        return {"imported": imported, "skipped": skipped}

    def snapshot_from_scan_file(self, path: Path) -> Dict[str, Any]:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        networks = document.get("networks", []) if isinstance(document, dict) else document
        if not isinstance(networks, list):
            raise ValueError("scan JSON must contain a network list")
        return self.snapshot_from_networks(networks, Path(path).stat().st_mtime)

    def replay_scan(self, path: Path) -> List[Dict[str, str]]:
        return self.analyze_snapshot(
            self.snapshot_from_scan_file(path), source=f"replay:{Path(path).name}", learn=False
        )

    def trust_bssid(self, bssid: str) -> bool:
        return self.store.set_trusted(bssid.strip().upper(), True)

    def export_incidents(self, destination: Optional[Path] = None) -> Path:
        directory = Path(self.core.config.get("output_dirs", {}).get("reports", "./reports"))
        directory.mkdir(parents=True, exist_ok=True)
        destination = destination or directory / f"anomaly_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        destination.write_text(json.dumps(self.store.recent_incidents(1000), indent=2), encoding="utf-8")
        return destination

    def _live_report(self, incidents: List[Dict[str, str]], snapshot: Dict[str, Any]) -> None:
        print_colored("\n=== AI Anomaly Detection Live Report ===", "cyan", bold=True)
        if not incidents:
            print_colored("No anomalies detected.", "green")
        for item in incidents:
            color = "red" if item["severity"] in ("critical", "high") else "yellow"
            print_colored(f"[{item['severity'].upper()}] {item['message']}", color)
        print_colored(
            f"Snapshot: {snapshot['count']} networks; average signal {snapshot['signal_avg']:.1f} dBm",
            "white",
        )

    def run_live_monitoring(self, interval: Optional[int] = None, learning_duration: Optional[int] = None) -> bool:
        from .monitor import MonitorEngine
        try:
            return self._run_live_monitoring(interval, learning_duration)
        except KeyboardInterrupt:
            print_colored("\nAnomaly monitoring stopped.", "yellow")
            return True
        finally:
            self.running = False
            MonitorEngine(self.core).prompt_restore_normal_mode(self.core.active_interface)

    def _run_live_monitoring(self, interval: Optional[int], learning_duration: Optional[int]) -> bool:
        if not self.ensure_prerequisites():
            return False
        config = self.core.config.get("ai", {})
        interval = max(1, int(interval or config.get("snapshot_interval", 30)))
        duration = max(1, int(config.get("snapshot_duration", 5)))
        sample_count = max(3, int(config.get("baseline_samples", 10)))

        if not self.baseline:
            requested_seconds = max(1, int(learning_duration)) if learning_duration is not None else sample_count * duration
            sample_count = (requested_seconds + duration - 1) // duration
            print_colored(f"Learning normal activity for about {requested_seconds} seconds...", "yellow")
            learning = []
            for index in range(sample_count):
                capture_duration = min(duration, requested_seconds - index * duration)
                snapshot = self._capture_snapshot(capture_duration)
                if snapshot is None:
                    print_colored(
                        f"  Baseline sample {index + 1}/{sample_count} failed; skipping it.",
                        "yellow",
                    )
                    continue
                learning.append(snapshot)
                self.store.add_snapshot(snapshot, source="baseline", interface=self.core.active_interface)
                self.store.learn_networks(snapshot["networks"])
                print_colored(f"  Baseline sample {index + 1}/{sample_count}", "blue")
            if not learning:
                print_colored("No baseline captures succeeded; monitoring was not started.", "red")
                return False
            self._train_model(learning)
        else:
            print_colored("Using the saved baseline and learned network patterns.", "green")

        print_colored("Passive anomaly monitoring started. Press Ctrl+C to stop.", "cyan", bold=True)
        self.running = True
        try:
            while self.running:
                started = time.monotonic()
                snapshot = self._capture_snapshot(duration)
                if snapshot is None:
                    print_colored("Snapshot capture failed; retaining the previous baseline.", "yellow")
                    remaining = interval - (time.monotonic() - started)
                    if remaining > 0:
                        time.sleep(remaining)
                    continue
                incidents = self.analyze_snapshot(snapshot, source="live", learn=True)
                self._live_report(incidents, snapshot)
                remaining = interval - (time.monotonic() - started)
                if remaining > 0:
                    time.sleep(remaining)
        except KeyboardInterrupt:
            print_colored("\nAnomaly monitoring stopped.", "yellow")
        finally:
            self.running = False
        return True

    def _compute_baseline(self, snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = [item["count"] for item in snapshots]
        signals = [item["signal_avg"] for item in snapshots if item["count"]]
        return {
            "sample_count": len(snapshots),
            "avg_count": float(np.mean(counts)) if counts else 0.0,
            "std_count": float(np.std(counts)) if len(counts) > 1 else 0.0,
            "avg_signal": float(np.mean(signals)) if signals else 0.0,
            "std_signal": float(np.std(signals)) if len(signals) > 1 else 0.0,
            "updated_at": time.time(),
        }
