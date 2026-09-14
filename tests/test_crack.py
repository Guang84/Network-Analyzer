"""Hardware-free tests for offline capture and wordlist selection."""

import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

from engines.crack import CrackEngine


class CrackEngineTests(unittest.TestCase):
    def make_engine(self, directory):
        core = Mock()
        core.config = {
            'wordlist': str(Path(directory) / 'configured.txt'),
            'output_dirs': {'handshakes': str(Path(directory) / 'handshakes')},
        }
        return CrackEngine(core)

    def test_offline_aircrack_command_does_not_use_sudo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'test.cap'
            wordlist = root / 'words.txt'
            capture.write_bytes(b'capture')
            wordlist.write_text('password\n', encoding='utf-8')
            engine = self.make_engine(root)
            process = Mock()
            process.stdout = iter(['KEY NOT FOUND\n'])
            process.wait.return_value = 1
            with (
                patch('engines.crack.shutil.which', return_value='/usr/bin/aircrack-ng'),
                patch('engines.crack.subprocess.Popen', return_value=process) as popen,
            ):
                self.assertFalse(engine.crack_password(capture, wordlist))
        command = popen.call_args.args[0]
        self.assertEqual(command[0], '/usr/bin/aircrack-ng')
        self.assertNotIn('sudo', command)

    def test_comma_candidates_create_private_ephemeral_wordlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'test.cap'
            capture.write_bytes(b'capture')
            engine = self.make_engine(root)
            observed = {}

            def execute(command, **_kwargs):
                candidate_file = Path(command[command.index('-w') + 1])
                observed['content'] = candidate_file.read_text(encoding='utf-8')
                observed['mode'] = candidate_file.stat().st_mode & 0o777
                observed['path'] = candidate_file
                process = Mock()
                process.stdout = iter(['KEY NOT FOUND\n'])
                process.wait.return_value = 1
                return process

            with (
                patch('engines.crack.shutil.which', return_value='/usr/bin/aircrack-ng'),
                patch('engines.crack.subprocess.Popen', side_effect=execute),
            ):
                self.assertFalse(engine.crack_candidates(capture, ['first', 'second']))

        self.assertEqual(observed['content'], 'first\nsecond\n')
        self.assertEqual(observed['mode'], 0o600)
        self.assertFalse(observed['path'].exists())

    def test_comma_input_is_trimmed_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = self.make_engine(directory)
            with patch(
                'engines.crack.input_colored',
                side_effect=['4', ' first, second,first,  third  '],
            ):
                self.assertEqual(
                    engine._select_wordlist_mode(),
                    ('candidates', ['first', 'second', 'third']),
                )

    def test_missing_aircrack_is_reported_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = self.make_engine(directory)
            with (
                patch('engines.crack.shutil.which', return_value=None),
                patch('engines.crack.subprocess.Popen') as popen,
            ):
                self.assertFalse(engine.crack_password(Path(directory) / 'missing.cap'))
        popen.assert_not_called()

    def test_empty_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'empty.cap'
            wordlist = root / 'words.txt'
            capture.touch()
            wordlist.write_text('password\n', encoding='utf-8')
            engine = self.make_engine(root)
            with (
                patch('engines.crack.shutil.which', return_value='/usr/bin/aircrack-ng'),
                patch('engines.crack.subprocess.Popen') as popen,
            ):
                self.assertFalse(engine.crack_password(capture, wordlist))
        popen.assert_not_called()

    def test_hash_extraction_uses_lowercase_j_and_verifies_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'test.cap'
            output = root / 'hashes'
            capture.write_bytes(b'capture')
            engine = self.make_engine(root)

            def execute(command, **_kwargs):
                prefix = Path(command[command.index('-j') + 1])
                Path(str(prefix) + '.hccapx').write_bytes(b'hash')
                return subprocess.CompletedProcess(command, 0, 'written', '')

            with (
                patch('engines.crack.shutil.which', return_value='/usr/bin/aircrack-ng'),
                patch('engines.crack.subprocess.run', side_effect=execute) as run,
            ):
                self.assertTrue(engine.extract_hash(capture, output))
        command = run.call_args.args[0]
        self.assertIn('-j', command)
        self.assertNotIn('-J', command)

    def test_hash_success_exit_without_output_file_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'test.cap'
            capture.write_bytes(b'capture')
            engine = self.make_engine(root)
            result = subprocess.CompletedProcess([], 0, 'nothing written', '')
            with (
                patch('engines.crack.shutil.which', return_value='/usr/bin/aircrack-ng'),
                patch('engines.crack.subprocess.run', return_value=result),
            ):
                self.assertFalse(engine.extract_hash(capture, root / 'hashes'))


if __name__ == '__main__':
    unittest.main()
