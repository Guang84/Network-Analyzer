"""Hardware-free tests for persistent and explainable anomaly detection."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engines.ai_anomaly import AIAnomalyEngine, FEATURE_SCHEMA, MODEL_FORMAT_VERSION


class FakeCore:
    active_interface = "wlan-testmon"

    def __init__(self, root: Path):
        self.config = {
            "ai": {
                "patterns_db": str(root / "patterns.db"),
                "model_path": str(root / "model.joblib"),
                "minimum_training_samples": 10,
                "signal_surge_db": 18,
                "alert_channel_changes": True,
            },
            "output_dirs": {"reports": str(root / "reports")},
        }


def network(bssid, essid="Office", security="WPA2", channel="6", signal="-60"):
    return {
        "bssid": bssid,
        "essid": essid,
        "encryption_type": security,
        "channel": channel,
        "signal": signal,
    }


class AIAnomalyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.engine = AIAnomalyEngine(FakeCore(self.root))

    def tearDown(self):
        self.engine.store.close()
        self.tempdir.cleanup()

    def test_learned_patterns_and_incidents_persist(self):
        snapshot = self.engine.snapshot_from_networks([
            network("00:11:22:33:44:55", essid="Cafe", security="Open")
        ])
        incidents = self.engine.analyze_snapshot(snapshot)
        self.assertEqual(incidents[0]["rule"], "new_open_ap")
        stats = self.engine.store.stats()
        self.assertEqual(stats["patterns"], 1)
        self.assertEqual(stats["incidents"], 1)
        self.assertTrue(self.engine.db_path.exists())

    def test_new_bssid_for_trusted_ssid_is_possible_evil_twin(self):
        trusted = network("00:11:22:33:44:55")
        self.engine.store.learn_networks([trusted])
        self.assertTrue(self.engine.trust_bssid(trusted["bssid"]))

        snapshot = self.engine.snapshot_from_networks([
            network("AA:BB:CC:DD:EE:FF", security="Open", signal="-30")
        ])
        incidents = self.engine.analyze_snapshot(snapshot, learn=False)
        rules = {item["rule"] for item in incidents}
        self.assertIn("possible_evil_twin", rules)

    def test_trusted_security_baseline_cannot_be_poisoned(self):
        bssid = "00:11:22:33:44:55"
        self.engine.store.learn_networks([network(bssid)])
        self.engine.trust_bssid(bssid)

        downgraded = self.engine.snapshot_from_networks([
            network(bssid, security="Open", channel="11")
        ])
        incidents = self.engine.analyze_snapshot(downgraded, learn=True)
        self.assertIn("encryption_downgrade", {item["rule"] for item in incidents})
        pattern = self.engine.store.get_pattern(bssid)
        self.assertEqual(pattern["security"], "WPA2")
        self.assertEqual(pattern["channel"], "6")

    def test_saved_scan_import_uses_real_network_features(self):
        scan = self.root / "scan.json"
        scan.write_text(json.dumps([
            network("00:11:22:33:44:55"),
            network("00:11:22:33:44:66", essid="Guest", security="WPA3"),
        ]), encoding="utf-8")
        result = self.engine.import_scan_files([scan], train=False)
        self.assertEqual(result, {"imported": 1, "skipped": 0})
        self.assertEqual(self.engine.store.stats()["observations"], 2)
        stored = self.engine.store.training_snapshots()
        self.assertEqual(stored[0]["count"], 2)

        repeated = self.engine.import_scan_files([scan], train=False)
        self.assertEqual(repeated, {"imported": 0, "skipped": 1})
        self.assertEqual(self.engine.store.stats()["observations"], 2)

    def test_incident_cooldown_reduces_persistent_alert_spam(self):
        snapshot = self.engine.snapshot_from_networks([
            network("00:11:22:33:44:55", essid="Cafe", security="Open")
        ])
        self.engine.analyze_snapshot(snapshot, learn=False)
        self.engine.analyze_snapshot(snapshot, learn=False)
        self.assertEqual(self.engine.store.stats()["incidents"], 1)

    def test_configured_legacy_json_is_migrated_once(self):
        self.engine.store.close()
        legacy = self.root / "old-patterns.json"
        legacy.write_text(json.dumps({
            "baseline": {"avg_count": 1, "std_count": 0, "avg_signal": -50},
            "history": [{"networks": [network("00:11:22:33:44:55")]}],
        }), encoding="utf-8")
        core = FakeCore(self.root)
        core.config["ai"]["patterns_db"] = str(legacy)
        self.engine = AIAnomalyEngine(core)
        self.assertEqual(self.engine.store.stats()["patterns"], 1)
        self.assertEqual(self.engine.baseline["avg_count"], 1)
        # Constructing a second engine against the same DB must not duplicate rows.
        second = AIAnomalyEngine(core)
        try:
            self.assertEqual(second.store.stats()["snapshots"], 1)
        finally:
            second.store.close()


    def test_evil_twin_stays_suspicious_after_learning(self):
        trusted = network("00:11:22:33:44:55")
        self.engine.store.learn_networks([trusted])
        self.engine.trust_bssid(trusted['bssid'])
        suspect = network("AA:BB:CC:DD:EE:FF", security="Open")
        # Even a previously learned candidate must be checked against trust.
        self.engine.store.learn_networks([suspect])
        for _ in range(2):
            incidents = self.engine.analyze_snapshot(self.engine.snapshot_from_networks([suspect]))
            self.assertIn('possible_evil_twin', {item['rule'] for item in incidents})
        self.assertEqual(self.engine.store.stats()['incidents'], 1)

    def test_training_round_trip_preserves_features(self):
        snapshot = self.engine.snapshot_from_networks([
            network('00:11:22:33:44:55', essid='Hidden'),
            network('00:11:22:33:44:66', security='WPA3'),
        ], timestamp=12345)
        self.engine.store.add_snapshot(snapshot)
        restored = self.engine._normalize_snapshot(self.engine.store.training_snapshots()[0])
        self.assertEqual(self.engine._extract_features(snapshot).tolist(),
                         self.engine._extract_features(restored).tolist())
        self.assertEqual(restored['timestamp'], 12345)

    def test_incident_status_and_trust_refresh_persist(self):
        ap = network('00:11:22:33:44:55')
        self.engine.store.learn_networks([ap])
        self.engine.trust_bssid(ap['bssid'])
        changed = network(ap['bssid'], essid='New Office', channel='11')
        self.engine.analyze_snapshot(self.engine.snapshot_from_networks([changed]))
        incident = self.engine.store.recent_incidents()[0]
        self.assertTrue(self.engine.store.set_incident_status(incident['id'], 'resolved'))
        self.assertEqual(self.engine.store.recent_incidents()[0]['status'], 'resolved')
        with self.assertRaises(ValueError):
            self.engine.store.set_incident_status(incident['id'], 'invalid')
        self.assertFalse(self.engine.store.set_incident_status(9999, 'open'))
        self.assertTrue(self.engine.store.approve_latest_observation(ap['bssid']))
        pattern = self.engine.store.get_pattern(ap['bssid'])
        self.assertEqual((pattern['essid'], pattern['channel'], pattern['trusted']),
                         ('New Office', '11', 1))
        self.assertTrue(self.engine.store.set_trusted(ap['bssid'], False))
        self.assertEqual(self.engine.store.get_pattern(ap['bssid'])['trusted'], 0)

    def test_learning_rate_updates_signal_but_surge_does_not(self):
        ap = network('00:11:22:33:44:55', signal='-60')
        self.engine.store.learn_networks([ap])
        self.engine.core.config['ai']['learning_rate'] = 0.25
        self.engine.analyze_snapshot(self.engine.snapshot_from_networks([dict(ap, signal='-52')]))
        self.assertEqual(self.engine.store.get_pattern(ap['bssid'])['signal_mean'], -58)
        self.engine.analyze_snapshot(self.engine.snapshot_from_networks([dict(ap, signal='-20')]))
        self.assertEqual(self.engine.store.get_pattern(ap['bssid'])['signal_mean'], -58)

    def test_live_monitoring_restores_on_failed_learning_and_interrupt(self):
        for capture in (Mock(return_value=None), Mock(side_effect=KeyboardInterrupt)):
            with patch.object(self.engine, 'ensure_prerequisites', return_value=True), \
                 patch.object(self.engine, '_capture_snapshot', capture), \
                 patch('engines.monitor.MonitorEngine') as monitor:
                self.engine.run_live_monitoring()
                monitor.return_value.prompt_restore_normal_mode.assert_called_once_with('wlan-testmon')
                self.assertFalse(self.engine.running)

    def test_learning_duration_controls_capture_budget(self):
        snapshot = self.engine.snapshot_from_networks([network('00:11:22:33:44:55')])
        self.engine.core.config['ai']['snapshot_duration'] = 5
        with patch.object(self.engine, 'ensure_prerequisites', return_value=True), \
             patch.object(self.engine, '_capture_snapshot', side_effect=[snapshot, snapshot, KeyboardInterrupt]) as capture, \
             patch.object(self.engine, '_train_model') as train, \
             patch('engines.monitor.MonitorEngine'):
            self.engine.run_live_monitoring(learning_duration=7)
        self.assertEqual([call.args[0] for call in capture.call_args_list[:2]], [5, 2])
        self.assertEqual(len(train.call_args.args[0]), 2)

    def test_old_model_requires_retraining(self):
        self.engine.model_path.touch()
        payload = {'model': Mock(), 'feature_schema': FEATURE_SCHEMA}
        with patch('engines.ai_anomaly.ML_AVAILABLE', True), \
             patch('engines.ai_anomaly.joblib') as joblib:
            joblib.load.return_value = payload
            self.assertIsNone(self.engine._load_model())
            payload['format_version'] = MODEL_FORMAT_VERSION
            self.assertIs(self.engine._load_model(), payload['model'])

    def test_unchanged_import_can_retrain_invalidated_model(self):
        scan = self.root / 'scan.json'
        scan.write_text(json.dumps([network('00:11:22:33:44:55')]))
        self.engine.import_scan_files([scan], train=False)
        with patch.object(self.engine, '_train_model') as train:
            result = self.engine.import_scan_files([scan])
        self.assertEqual(result, {'imported': 0, 'skipped': 1})
        self.assertEqual(len(train.call_args.args[0]), 1)

    def test_baseline_approval_does_not_add_observations(self):
        ap = network('00:11:22:33:44:55')
        self.engine.analyze_snapshot(self.engine.snapshot_from_networks([ap]))
        before = self.engine.store.get_pattern(ap['bssid'])
        self.assertTrue(self.engine.store.approve_latest_observation(ap['bssid']))
        after = self.engine.store.get_pattern(ap['bssid'])
        self.assertEqual(after['times_seen'], before['times_seen'])
        self.assertEqual(after['first_seen'], before['first_seen'])


if __name__ == "__main__":
    unittest.main()
