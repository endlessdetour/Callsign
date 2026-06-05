import multiprocessing
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _worker(queue, hold_seconds):
    from client.windows import gui_client

    acquired = gui_client._acquire_single_instance_lock()
    queue.put(acquired)
    try:
        if acquired:
            time.sleep(hold_seconds)
    finally:
        if acquired:
            gui_client._release_single_instance_lock()


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    multiprocessing.set_start_method("spawn", force=True)
    suffix = str(int(time.time() * 1000))
    os.environ["CALLSIGN_SINGLE_INSTANCE_MUTEX"] = f"Local\\CallsignSingleInstanceTest_{suffix}"
    os.environ["CALLSIGN_SINGLE_INSTANCE_LOCKFILE"] = f"callsign.single_instance.test.{suffix}.lock"

    q1 = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=_worker, args=(q1, 3.0), daemon=True)
    p1.start()
    first = q1.get(timeout=5)
    assert_true(first is True, "first process should acquire single-instance lock")

    # Let the first process hold the lock before starting second process.
    time.sleep(0.5)

    q2 = multiprocessing.Queue()
    p2 = multiprocessing.Process(target=_worker, args=(q2, 0.2), daemon=True)
    p2.start()
    second = q2.get(timeout=5)

    p2.join(timeout=5)
    p1.join(timeout=5)

    assert_true(second is False, "second process should be blocked by single-instance lock")
    print("gui-single-instance-smoke: PASS")


if __name__ == "__main__":
    main()
