import tkinter as tk
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.windows import gui_client


# Disable real tray thread for deterministic method-level tests.
_original_init_tray = gui_client.ClientGui._init_tray
gui_client.ClientGui._init_tray = lambda self: None


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def test_close_minimize_and_restore():
    root = tk.Tk()
    app = gui_client.ClientGui(root)
    root.update_idletasks()

    app.on_close()
    root.update_idletasks()
    assert_true(app._hidden_to_tray, "window close should mark hidden-to-tray")

    app._restore_from_tray()
    root.update_idletasks()
    assert_true(not app._hidden_to_tray, "restore from tray should unhide")

    app._stop_tray()
    root.destroy()


def test_tray_toggle_callbacks():
    root = tk.Tk()
    app = gui_client.ClientGui(root)
    calls = {"start": 0, "stop": 0}

    app.start_client = lambda: calls.__setitem__("start", calls["start"] + 1)
    app.stop_client = lambda: calls.__setitem__("stop", calls["stop"] + 1)

    app.proc = None
    app._tray_toggle_connection()
    assert_true(calls["start"] == 1, "tray toggle should call start when disconnected")

    app.proc = object()
    app._tray_toggle_connection()
    assert_true(calls["stop"] == 1, "tray toggle should call stop when connected")

    app._stop_tray()
    root.destroy()


def test_exit_app_disconnects_and_cleans():
    root = tk.Tk()
    app = gui_client.ClientGui(root)
    calls = {"stop": 0, "tray_stop": 0, "destroy": 0}

    app.stop_client = lambda: calls.__setitem__("stop", calls["stop"] + 1)
    app._stop_tray = lambda: calls.__setitem__("tray_stop", calls["tray_stop"] + 1)
    app.root.destroy = lambda: calls.__setitem__("destroy", calls["destroy"] + 1)

    app.exit_app()
    assert_true(calls["stop"] == 1, "exit should disconnect first")
    assert_true(calls["tray_stop"] == 1, "exit should stop tray icon")
    assert_true(calls["destroy"] == 1, "exit should destroy GUI")


def test_disconnect_exit_code_semantics():
    root = tk.Tk()
    app = gui_client.ClientGui(root)

    class FakeProc:
        stdout = []

        def wait(self):
            return 1

    fake = FakeProc()
    app.proc = fake
    app._disconnect_requested = True
    app._read_output()
    logs = []
    while not app.log_queue.empty():
        logs.append(app.log_queue.get())
    assert_true(any("client disconnected" in line for line in logs), "requested disconnect should log disconnected")
    assert_true(not any("exited with code 1" in line for line in logs), "requested disconnect should not report exit code 1")

    app.proc = fake
    app._disconnect_requested = False
    app._read_output()
    logs = []
    while not app.log_queue.empty():
        logs.append(app.log_queue.get())
    assert_true(any("exited with code 1" in line for line in logs), "unexpected non-zero exit should still be reported")

    app._stop_tray()
    root.destroy()


if __name__ == "__main__":
    try:
        test_close_minimize_and_restore()
        test_tray_toggle_callbacks()
        test_exit_app_disconnects_and_cleans()
        test_disconnect_exit_code_semantics()
        print("gui-tray-smoke-tests: PASS")
    finally:
        gui_client.ClientGui._init_tray = _original_init_tray
