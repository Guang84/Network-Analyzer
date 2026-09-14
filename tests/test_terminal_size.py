"""Exercise live terminal sizing using real PTYs without X11 or radio tools."""
import fcntl
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from unittest.mock import patch

from engines.terminal_manager import TerminalManager


class TerminalSizeTests(unittest.TestCase):
    def test_zero_close_delay_has_no_countdown_or_pause(self):
        script = TerminalManager._command_script('test', ['true'], close_delay=0)
        self.assertNotIn('sleep', script)
        self.assertNotIn('Closing', script)
        self.assertNotIn('read -r', script)
        live = TerminalManager._live_fifo_script('test', Path('/tmp/test-fifo'), 'Stop', 'Done')
        self.assertNotIn('sleep', live)

    def test_live_commands_use_viewer_size_and_receive_resize(self):
        for background in (False, True):
            with self.subTest(background=background), tempfile.TemporaryDirectory() as directory:
                master, slave = os.openpty()
                self.addCleanup(os.close, master)
                self.addCleanup(os.close, slave)
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 42, 120, 0, 0))
                result = Path(directory) / 'size'
                code = (
                    'import os,signal,time,pathlib; '
                    f'p=pathlib.Path({str(result)!r}); '
                    'report=lambda *args: p.write_text(str(os.get_terminal_size(1))); '
                    'signal.signal(signal.SIGWINCH,report); report(); time.sleep(30)'
                )
                manager = TerminalManager()
                viewers = []

                def launch(_title, script, _geometry):
                    process = subprocess.Popen(['sh', '-c', script], stdin=slave,
                                               stdout=slave, stderr=slave, start_new_session=True)
                    viewers.append(process)
                    return process

                def wait_for_size(columns):
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline:
                        if result.exists() and f'columns={columns},' in result.read_text():
                            return
                        time.sleep(0.02)
                    self.fail(f'Producer did not receive terminal width {columns}')

                worker = None
                handle = None
                try:
                    with patch.object(manager, '_terminal_commands', return_value=[['simulated-viewer']]), \
                         patch.object(manager, '_launch_terminal_process', side_effect=launch):
                        command = [sys.executable, '-c', code]
                        if background:
                            handle = manager.start_live_command('test', command)
                            self.assertIsNotNone(handle)
                        else:
                            worker = threading.Thread(target=manager.run_live_command,
                                                      args=('test', command), kwargs={'timeout': 2})
                            worker.start()
                        wait_for_size(120)
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 60, 180, 0, 0))
                        wait_for_size(180)
                        if handle:
                            handle.terminate()
                            handle.producer.wait(timeout=3)
                        if worker:
                            worker.join(timeout=10)
                            self.assertFalse(worker.is_alive())
                finally:
                    if handle and handle.poll() is None:
                        handle.terminate()
                    for viewer in viewers:
                        if viewer.poll() is None:
                            os.killpg(viewer.pid, signal.SIGTERM)
                        viewer.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
