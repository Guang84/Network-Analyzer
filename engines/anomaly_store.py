#!/usr/bin/env python3
"""SQLite persistence for learned wireless patterns and anomaly incidents."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class AnomalyStore:
    """Small, local database used by the passive anomaly detector."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY,
                observed_at REAL NOT NULL,
                source TEXT NOT NULL,
                interface TEXT,
                features_json TEXT NOT NULL,
                anomaly_score REAL,
                is_anomaly INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY,
                snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                bssid TEXT,
                essid TEXT,
                channel TEXT,
                security TEXT,
                signal REAL
            );
            CREATE INDEX IF NOT EXISTS observations_bssid ON observations(bssid);
            CREATE INDEX IF NOT EXISTS observations_essid ON observations(essid);
            CREATE TABLE IF NOT EXISTS patterns (
                bssid TEXT PRIMARY KEY,
                essid TEXT,
                security TEXT,
                channel TEXT,
                signal_mean REAL,
                signal_samples INTEGER NOT NULL DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                trusted INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS patterns_essid ON patterns(essid);
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY,
                snapshot_id INTEGER REFERENCES snapshots(id) ON DELETE SET NULL,
                detected_at REAL NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                entity TEXT,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );
            CREATE INDEX IF NOT EXISTS incidents_detected_at ON incidents(detected_at DESC);
            """
        )
        self.connection.commit()

    @staticmethod
    def _signal(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def add_snapshot(
        self,
        snapshot: Dict[str, Any],
        source: str = "live",
        interface: Optional[str] = None,
        anomaly_score: Optional[float] = None,
        is_anomaly: bool = False,
    ) -> int:
        features = {
            key: snapshot.get(key)
            for key in ("count", "signal_avg", "encryption_dist", "channel_dist")
        }
        cursor = self.connection.execute(
            """INSERT INTO snapshots
               (observed_at, source, interface, features_json, anomaly_score, is_anomaly)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                float(snapshot.get("timestamp", time.time())), source, interface,
                json.dumps(features, sort_keys=True), anomaly_score, int(is_anomaly),
            ),
        )
        snapshot_id = int(cursor.lastrowid)
        rows = []
        for network in snapshot.get("networks", []):
            rows.append((
                snapshot_id,
                str(network.get("bssid", "")).upper() or None,
                network.get("essid") or None,
                str(network.get("channel", "")) or None,
                network.get("encryption_type") or network.get("encryption") or "Unknown",
                self._signal(network.get("signal")),
            ))
        self.connection.executemany(
            """INSERT INTO observations
               (snapshot_id, bssid, essid, channel, security, signal)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self.connection.commit()
        return snapshot_id

    def learn_networks(self, networks: Iterable[Dict[str, Any]], learning_rate: Optional[float] = None) -> None:
        if learning_rate is not None and not 0 < learning_rate <= 1:
            raise ValueError("learning_rate must be greater than 0 and at most 1")
        now = time.time()
        for network in networks:
            bssid = str(network.get("bssid", "")).strip().upper()
            if not bssid:
                continue
            essid = str(network.get("essid") or "Hidden").strip()
            security = str(network.get("encryption_type") or network.get("encryption") or "Unknown")
            channel = str(network.get("channel", "")).strip()
            signal = self._signal(network.get("signal"))
            existing = self.get_pattern(bssid)
            if existing:
                samples = int(existing["signal_samples"])
                old_mean = existing["signal_mean"]
                if signal is None:
                    mean = old_mean
                elif old_mean is None or samples == 0:
                    mean, samples = signal, 1
                else:
                    mean = (float(old_mean) + learning_rate * (signal - float(old_mean))
                            if learning_rate is not None else
                            ((float(old_mean) * samples) + signal) / (samples + 1))
                    samples += 1
                # Trusted identity attributes are an approved baseline. Do not
                # let a suspicious observation silently replace that baseline.
                learned_essid = existing["essid"] if existing["trusted"] else essid
                learned_security = existing["security"] if existing["trusted"] else security
                learned_channel = existing["channel"] if existing["trusted"] else channel
                self.connection.execute(
                    """UPDATE patterns SET essid=?, security=?, channel=?, signal_mean=?,
                       signal_samples=?, last_seen=?, times_seen=times_seen+1 WHERE bssid=?""",
                    (learned_essid, learned_security, learned_channel, mean, samples, now, bssid),
                )
            else:
                self.connection.execute(
                    """INSERT INTO patterns
                       (bssid, essid, security, channel, signal_mean, signal_samples,
                        first_seen, last_seen, times_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (bssid, essid, security, channel, signal, int(signal is not None), now, now),
                )
        self.connection.commit()

    def get_pattern(self, bssid: str) -> Optional[Dict[str, Any]]:
        row = self.connection.execute(
            "SELECT * FROM patterns WHERE bssid=?", (bssid.upper(),)
        ).fetchone()
        return dict(row) if row else None

    def patterns_for_essid(self, essid: str) -> List[Dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM patterns WHERE essid=? ORDER BY trusted DESC, times_seen DESC", (essid,)
        ).fetchall()
        return [dict(row) for row in rows]

    def set_trusted(self, bssid: str, trusted: bool = True) -> bool:
        cursor = self.connection.execute(
            "UPDATE patterns SET trusted=? WHERE bssid=?", (int(trusted), bssid.upper())
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def trusted_patterns(self) -> List[Dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM patterns WHERE trusted=1 ORDER BY essid, bssid"
        ).fetchall()]

    def latest_observation(self, bssid: str) -> Optional[Dict[str, Any]]:
        row = self.connection.execute(
            """SELECT o.* FROM observations o JOIN snapshots s ON s.id=o.snapshot_id
               WHERE o.bssid=? ORDER BY s.observed_at DESC, o.id DESC LIMIT 1""",
            (bssid.strip().upper(),),
        ).fetchone()
        return dict(row) if row else None

    def approve_latest_observation(self, bssid: str) -> bool:
        observation = self.latest_observation(bssid)
        if observation is None:
            return False
        bssid = bssid.strip().upper()
        with self.connection:
            self.connection.execute(
                """INSERT INTO patterns
                   (bssid, essid, security, channel, signal_mean, signal_samples,
                    first_seen, last_seen, trusted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                   ON CONFLICT(bssid) DO UPDATE SET
                   essid=excluded.essid, security=excluded.security,
                   channel=excluded.channel, signal_mean=excluded.signal_mean,
                   signal_samples=excluded.signal_samples, trusted=1""",
                (bssid, observation['essid'] or 'Hidden', observation['security'],
                 observation['channel'], observation['signal'],
                 int(observation['signal'] is not None), time.time(), time.time()),
            )
        return True

    def set_incident_status(self, incident_id: int, status: str) -> bool:
        if status not in ('open', 'acknowledged', 'resolved'):
            raise ValueError("Invalid incident status")
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE incidents SET status=? WHERE id=?", (status, incident_id),
            )
        return cursor.rowcount > 0

    def learned_patterns(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            """SELECT * FROM patterns
               ORDER BY trusted DESC, last_seen DESC LIMIT ?""", (limit,)
        ).fetchall()]

    def add_incidents(
        self,
        snapshot_id: int,
        incidents: Iterable[Dict[str, str]],
        cooldown_seconds: int = 0,
    ) -> int:
        now = time.time()
        inserted = 0
        for item in incidents:
            entity = item.get("entity")
            if cooldown_seconds > 0:
                duplicate = self.connection.execute(
                    """SELECT 1 FROM incidents
                       WHERE rule=? AND entity IS ? AND detected_at>=? LIMIT 1""",
                    (item["rule"], entity, now - cooldown_seconds),
                ).fetchone()
                if duplicate:
                    continue
            self.connection.execute(
                """INSERT INTO incidents
                   (snapshot_id, detected_at, rule, severity, entity, message)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    snapshot_id, now, item["rule"], item["severity"],
                    entity, item["message"],
                ),
            )
            inserted += 1
        self.connection.commit()
        return inserted

    def recent_incidents(self, limit: int = 25) -> List[Dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM incidents ORDER BY detected_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def training_snapshots(self, limit: int = 1000) -> List[Dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT id, observed_at, features_json FROM snapshots WHERE is_anomaly=0
               ORDER BY observed_at DESC LIMIT ?""", (limit,)
        ).fetchall()
        result = []
        for row in reversed(rows):
            snapshot = json.loads(row['features_json'])
            snapshot['timestamp'] = row['observed_at']
            snapshot['networks'] = [dict(item) for item in self.connection.execute(
                """SELECT bssid, essid, channel, security AS encryption_type, signal
                   FROM observations WHERE snapshot_id=? ORDER BY id""", (row['id'],)
            ).fetchall()]
            result.append(snapshot)
        return result

    def stats(self) -> Dict[str, int]:
        result = {}
        for table in ("snapshots", "observations", "patterns", "incidents"):
            result[table] = int(self.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0])
        result["trusted_patterns"] = int(self.connection.execute(
            "SELECT COUNT(*) FROM patterns WHERE trusted=1"
        ).fetchone()[0])
        result["open_incidents"] = int(self.connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status='open'"
        ).fetchone()[0])
        return result

    def set_metadata(self, key: str, value: Any) -> None:
        self.connection.execute(
            """INSERT INTO metadata(key, value) VALUES(?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (key, json.dumps(value)),
        )
        self.connection.commit()

    def get_metadata(self, key: str, default: Any = None) -> Any:
        row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def close(self) -> None:
        self.connection.close()
