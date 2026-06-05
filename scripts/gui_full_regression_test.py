import sys
from pathlib import Path
import tkinter as tk

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.windows import gui_client


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


_original_init_tray = gui_client.ClientGui._init_tray

gui_client.ClientGui._init_tray = lambda self: None


class DummyProc:
    def __init__(self, lines=None, wait_code=0):
        self.stdout = lines or []
        self._wait_code = wait_code
        self.killed = False

    def wait(self, timeout=None):
        return self._wait_code

    def send_signal(self, _sig):
        return None

    def terminate(self):
        return None

    def kill(self):
        self.killed = True


def test_profile_crud(app):
    app.control_url.set("https://example-a")
    app.access_token.set("t1")
    app.profile_name.set("p1")
    app.save_profile()
    assert_true("p1" in app.profiles, "save profile should persist profile")
    assert_true(app.profiles["p1"].get("access_token") == "t1", "save profile should persist access token")

    old_askstring = gui_client.simpledialog.askstring
    gui_client.simpledialog.askstring = lambda *args, **kwargs: "p2"
    try:
        app.control_url.set("https://example-b")
        app.access_token.set("t2")
        app.save_profile_as()
        assert_true("p2" in app.profiles, "save as should create new profile")
        assert_true(app.profiles["p2"].get("access_token") == "t2", "save as should persist access token")
    finally:
        gui_client.simpledialog.askstring = old_askstring

    old_askyesno = gui_client.messagebox.askyesno
    gui_client.messagebox.askyesno = lambda *args, **kwargs: True
    try:
        app.profile_name.set("p2")
        app.delete_profile()
        assert_true("p2" not in app.profiles, "delete should remove selected profile")
    finally:
        gui_client.messagebox.askyesno = old_askyesno


def test_input_guards(app):
    app.clear_log()
    app.control_url.set("")
    app.access_token.set("")
    app.start_client()
    logs = app.log_text.get("1.0", "end")
    assert_true("control/access token cannot be empty" in logs, "empty control/token should be rejected")

    app.clear_log()
    app.control_url.set("https://overlay.example.com")
    app.access_token.set("dev-token")
    old_is_admin = app._is_admin
    app._is_admin = lambda: False
    try:
        app.start_client()
        logs = app.log_text.get("1.0", "end")
        assert_true("Wintun + Apply Routes requires running GUI as Administrator" in logs, "non-admin mode should be rejected")
    finally:
        app._is_admin = old_is_admin


def test_connect_disconnect_flow(app):
    app.clear_log()
    app.control_url.set("https://overlay.example.com")
    app.access_token.set("dev-token")
    old_is_admin = app._is_admin
    app._is_admin = lambda: True

    old_popen = gui_client.subprocess.Popen
    old_thread = gui_client.threading.Thread

    class FakeThread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            # Intentionally no-op to keep GUI in connected state until test triggers read path.
            return None

    def fake_popen(*args, **kwargs):
        return DummyProc(lines=["[tunnel] connected\n", "[control] heartbeat ok\n"], wait_code=0)

    gui_client.subprocess.Popen = fake_popen
    gui_client.threading.Thread = FakeThread
    try:
        app.start_client()
        app.root.update_idletasks()
        app.root.update()
        assert_true(app.proc is not None, "start should create a client process")
        assert_true("client started" in app.log_text.get("1.0", "end"), "start should append started log")

        # Simulate read thread completing.
        app._read_output()
        app.root.update_idletasks()
        app.root.update()
        assert_true(app.proc is None, "process should clear after read loop exits")

        # Simulate manual disconnect with non-zero code; should not surface as error when requested.
        app.proc = DummyProc(lines=[], wait_code=1)
        app._disconnect_requested = True
        app._read_output()
        buffered = []
        while not app.log_queue.empty():
            buffered.append(app.log_queue.get())
        assert_true(any("client disconnected" in line for line in buffered), "requested disconnect should log disconnected")
        assert_true(not any("exited with code 1" in line for line in buffered), "requested disconnect should hide code 1")
    finally:
        gui_client.subprocess.Popen = old_popen
        gui_client.threading.Thread = old_thread
        app._is_admin = old_is_admin


def test_window_close_and_exit(app):
    app.on_close()
    assert_true(app._hidden_to_tray, "clicking X should hide to tray")

    calls = {"stopped": 0, "tray": 0, "destroy": 0}
    app.stop_client = lambda: calls.__setitem__("stopped", calls["stopped"] + 1)
    app._stop_tray = lambda: calls.__setitem__("tray", calls["tray"] + 1)
    app.root.destroy = lambda: calls.__setitem__("destroy", calls["destroy"] + 1)
    app.exit_app()
    assert_true(calls["stopped"] == 1, "exit should stop client")
    assert_true(calls["tray"] == 1, "exit should stop tray")
    assert_true(calls["destroy"] == 1, "exit should destroy root")


def main():
    root = tk.Tk()
    app = gui_client.ClientGui(root)
    try:
        test_profile_crud(app)
        test_input_guards(app)
        test_connect_disconnect_flow(app)
        test_window_close_and_exit(app)
        print("gui-full-regression: PASS")
    finally:
        try:
            app._stop_tray()
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            pass
        gui_client.ClientGui._init_tray = _original_init_tray


if __name__ == "__main__":
    main()
