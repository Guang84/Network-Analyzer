#!/usr/bin/env python3
"""Persistent inventory of every access point observed by Network Analyzer."""

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class NetworkInventory:
    """Store one durable record per BSSID plus one sighting per capture."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA foreign_keys = ON')
        self.connection.execute('PRAGMA journal_mode = WAL')
        self.connection.execute('PRAGMA busy_timeout = 10000')
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS networks (
                bssid TEXT PRIMARY KEY,
                essid TEXT,
                channel TEXT,
                encryption TEXT,
                strongest_signal INTEGER,
                latest_signal INTEGER,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                seen_in_captures INTEGER NOT NULL DEFAULT 1,
                last_source TEXT
            );
            CREATE TABLE IF NOT EXISTS sightings (
                bssid TEXT NOT NULL REFERENCES networks(bssid) ON DELETE CASCADE,
                capture_id TEXT NOT NULL,
                observed_at REAL NOT NULL,
                PRIMARY KEY (bssid, capture_id)
            );
            CREATE INDEX IF NOT EXISTS networks_last_seen
                ON networks(last_seen DESC);
            """
        )
        self.connection.commit()

    @staticmethod
    def _signal(network: Dict[str, Any]) -> Optional[int]:
        try:
            return int(float(str(network.get('signal', '')).strip()))
        except (TypeError, ValueError):
            return None

    def update(
        self,
        networks: Iterable[Dict[str, Any]],
        capture_id: str,
        observed_at: Optional[float] = None,
    ) -> int:
        """Upsert observations and return the number of unique BSSIDs seen."""
        now = float(observed_at if observed_at is not None else time.time())
        saved = 0
        seen = set()
        for network in networks:
            bssid = str(network.get('bssid', '')).strip().upper()
            if not bssid or bssid in seen:
                continue
            seen.add(bssid)
            essid = str(network.get('essid') or 'Hidden').strip() or 'Hidden'
            channel = str(network.get('channel', '')).strip()
            encryption = str(
                network.get('encryption_type') or network.get('encryption') or 'Unknown'
            )
            signal = self._signal(network)
            source = str(network.get('source') or capture_id)
            self.connection.execute(
                """
                INSERT OR IGNORE INTO networks
                    (bssid, essid, channel, encryption, strongest_signal,
                     latest_signal, first_seen, last_seen, seen_in_captures, last_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (bssid, essid, channel, encryption, signal, signal, now, now, source),
            )
            sighting = self.connection.execute(
                'INSERT OR IGNORE INTO sightings (bssid, capture_id, observed_at) VALUES (?, ?, ?)',
                (bssid, capture_id, now),
            )
            increment = 1 if sighting.rowcount else 0
            self.connection.execute(
                """
                UPDATE networks SET
                    essid = CASE WHEN ? != 'Hidden' THEN ? ELSE essid END,
                    channel = CASE WHEN ? != '' THEN ? ELSE channel END,
                    encryption = CASE WHEN ? != 'Unknown' THEN ? ELSE encryption END,
                    strongest_signal = CASE
                        WHEN ? IS NULL THEN strongest_signal
                        WHEN strongest_signal IS NULL THEN ?
                        ELSE MAX(strongest_signal, ?)
                    END,
                    latest_signal = COALESCE(?, latest_signal),
                    last_seen = ?,
                    seen_in_captures = seen_in_captures + ?,
                    last_source = ?
                WHERE bssid = ?
                """,
                (
                    essid, essid, channel, channel, encryption, encryption,
                    signal, signal, signal, signal, now, increment, source, bssid,
                ),
            )
            saved += 1
        self.connection.commit()
        return saved

    def previous(self, before: float, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT * FROM networks
            WHERE last_seen < ?
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (float(before), int(limit)),
        ).fetchall()
        return [dict(row) for row in rows]

    def all_networks(self, limit: int = 1000) -> List[Dict[str, Any]]:
        rows = self.connection.execute(
            'SELECT * FROM networks ORDER BY last_seen DESC LIMIT ?',
            (int(limit),),
        ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.connection.close()
