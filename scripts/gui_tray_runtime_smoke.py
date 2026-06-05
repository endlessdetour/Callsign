import sys
import time
from pathlib import Path
import tkinter as tk

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.windows.gui_client import ClientGui


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGui(root)
    root.update_idletasks()
    root.update()
    time.sleep(0.3)
    if app.tray_icon is None or app.tray_icon._thread is None or not app.tray_icon._thread.is_alive():
        raise RuntimeError("tray thread is not alive")

    app.on_close()
    root.update_idletasks()
    root.update()
    if not app._hidden_to_tray:
        raise RuntimeError("window did not hide to tray")

    time.sleep(0.5)
    app._restore_from_tray()
    root.update_idletasks()
    root.update()
    if app._hidden_to_tray:
        raise RuntimeError("window did not restore from tray")

    app.exit_app()
    print("gui-tray-runtime-smoke: PASS")
