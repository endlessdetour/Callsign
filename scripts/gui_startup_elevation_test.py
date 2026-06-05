import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.windows import gui_client


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def run_case(is_admin: bool, attempted: bool, relaunch_ok: bool, already_running: bool = False):
    calls = {"fatal": 0, "info": 0, "relaunch": 0, "tk": 0, "acquire": 0, "release": 0}

    old_argv = sys.argv[:]
    old_is_admin = gui_client._is_admin_user
    old_info = gui_client._show_info_popup
    old_fatal = gui_client._show_fatal_error
    old_relaunch = gui_client._request_uac_relaunch
    old_acquire = gui_client._acquire_single_instance_lock
    old_release = gui_client._release_single_instance_lock
    old_tk = gui_client.tk.Tk

    class FakeTk:
        def __init__(self):
            calls["tk"] += 1

        def mainloop(self):
            return None

    class FakeStyle:
        def __init__(self, _):
            pass

        def theme_names(self):
            return []

    old_style = gui_client.ttk.Style
    old_client_gui = gui_client.ClientGui

    class FakeClientGui:
        def __init__(self, _root):
            return None

        def append_log(self, _msg):
            return None

    try:
        sys.argv = ["gui_client.py"] + (["--elevated-relaunch"] if attempted else [])
        gui_client._is_admin_user = lambda: is_admin
        gui_client._show_info_popup = lambda _m: calls.__setitem__("info", calls["info"] + 1)
        gui_client._show_fatal_error = lambda _m: calls.__setitem__("fatal", calls["fatal"] + 1)
        gui_client._request_uac_relaunch = lambda: calls.__setitem__("relaunch", calls["relaunch"] + 1) or relaunch_ok
        gui_client._acquire_single_instance_lock = lambda: calls.__setitem__("acquire", calls["acquire"] + 1) or (not already_running)
        gui_client._release_single_instance_lock = lambda: calls.__setitem__("release", calls["release"] + 1)
        gui_client.tk.Tk = FakeTk
        gui_client.ttk.Style = FakeStyle
        gui_client.ClientGui = FakeClientGui

        gui_client.main()
        return calls
    finally:
        sys.argv = old_argv
        gui_client._is_admin_user = old_is_admin
        gui_client._show_info_popup = old_info
        gui_client._show_fatal_error = old_fatal
        gui_client._request_uac_relaunch = old_relaunch
        gui_client._acquire_single_instance_lock = old_acquire
        gui_client._release_single_instance_lock = old_release
        gui_client.tk.Tk = old_tk
        gui_client.ttk.Style = old_style
        gui_client.ClientGui = old_client_gui


def main():
    # Case 1: already admin -> normal startup path.
    c1 = run_case(is_admin=True, attempted=False, relaunch_ok=False)
    assert_true(c1["tk"] == 1, "admin startup should create UI")
    assert_true(c1["info"] == 0 and c1["fatal"] == 0 and c1["relaunch"] == 0, "admin startup should not trigger elevation prompts")
    assert_true(c1["acquire"] == 1 and c1["release"] == 1, "admin startup should acquire and release lock")

    # Case 2: non-admin first launch and relaunch accepted -> return without fatal.
    c2 = run_case(is_admin=False, attempted=False, relaunch_ok=True)
    assert_true(c2["info"] == 1, "non-admin startup should show info prompt")
    assert_true(c2["relaunch"] == 1, "non-admin startup should request UAC relaunch")
    assert_true(c2["fatal"] == 0, "successful relaunch request should not show fatal")
    assert_true(c2["tk"] == 0, "non-admin instance should not build UI")
    assert_true(c2["acquire"] == 1 and c2["release"] >= 1, "successful relaunch should release lock before exit")

    # Case 3: non-admin, relaunch denied -> fatal and exit.
    c3 = run_case(is_admin=False, attempted=False, relaunch_ok=False)
    assert_true(c3["info"] == 1, "denied relaunch still shows info prompt")
    assert_true(c3["relaunch"] == 1, "denied relaunch still attempts UAC")
    assert_true(c3["fatal"] == 1, "denied relaunch should show fatal")
    assert_true(c3["tk"] == 0, "denied relaunch should not create UI")
    assert_true(c3["acquire"] == 1 and c3["release"] == 1, "denied relaunch should release lock")

    # Case 4: elevated relaunch flag but still non-admin -> fatal directly.
    c4 = run_case(is_admin=False, attempted=True, relaunch_ok=False)
    assert_true(c4["info"] == 0, "second launch without admin should skip info and fail directly")
    assert_true(c4["relaunch"] == 0, "second launch without admin should not loop relaunch")
    assert_true(c4["fatal"] == 1, "second launch without admin should show fatal")
    assert_true(c4["tk"] == 0, "second launch without admin should not create UI")
    assert_true(c4["acquire"] == 1 and c4["release"] == 1, "failed elevated relaunch should release lock")

    # Case 5: second instance detected -> info popup and no UI startup.
    c5 = run_case(is_admin=True, attempted=False, relaunch_ok=False, already_running=True)
    assert_true(c5["info"] == 1, "already-running check should notify user")
    assert_true(c5["tk"] == 0, "already-running check should skip UI startup")
    assert_true(c5["relaunch"] == 0 and c5["fatal"] == 0, "already-running check should avoid unrelated startup paths")
    assert_true(c5["acquire"] == 1 and c5["release"] == 0, "already-running path should not release unacquired lock")

    print("gui-startup-elevation-tests: PASS")


if __name__ == "__main__":
    main()
