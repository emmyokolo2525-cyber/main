import time
import threading
from unittest.mock import patch, MagicMock

from flask import Flask, jsonify

from admission import AdmissionController, require_capacity, _get_client_identity


def test_admission_controller_capacity_limits():
    # max_concurrent = 2
    # max_queue = 1
    # max_per_identity = 3
    controller = AdmissionController(
        max_concurrent=2,
        max_queue=1,
        max_per_identity=3,
        timeout_seconds=0.1
    )

    # 1. Acquire up to concurrency limit
    ok1, reason1 = controller.acquire("client1")
    assert ok1 is True

    ok2, reason2 = controller.acquire("client2")
    assert ok2 is True

    # 2. Acquire when full but queue has space
    def acquire_delayed():
        # This will wait in the queue and then timeout
        return controller.acquire("client3")

    thread = threading.Thread(target=acquire_delayed)
    thread.start()
    
    # Let it get in the queue
    time.sleep(0.05)
    
    # 3. Queue is now full (1/1). The next acquire should fail immediately
    ok4, reason4 = controller.acquire("client4")
    assert ok4 is False
    assert reason4 == "queue_full"

    thread.join()

    # 4. Release slots
    controller.release("client1")
    controller.release("client2")

    # Now it should be possible to acquire again
    ok5, reason5 = controller.acquire("client5")
    assert ok5 is True


def test_admission_controller_identity_limit():
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=2,
        timeout_seconds=0.1
    )

    # Acquire up to identity limit
    ok1, _ = controller.acquire("user_A")
    assert ok1 is True
    ok2, _ = controller.acquire("user_A")
    assert ok2 is True

    # Third time fails for this user
    ok3, reason = controller.acquire("user_A")
    assert ok3 is False
    assert reason == "identity_limit"

    # But another user can acquire
    ok4, _ = controller.acquire("user_B")
    assert ok4 is True


def test_admission_controller_decorator():
    app = Flask(__name__)

    controller = AdmissionController(
        max_concurrent=1,
        max_queue=0,
        max_per_identity=1,
        timeout_seconds=0.1
    )

    @app.route("/test", methods=["GET"])
    @require_capacity(controller)
    def test_route():
        time.sleep(0.2)
        return jsonify({"ok": True})

    client = app.test_client()

    # Mock IP address to simulate same client
    environ = {"REMOTE_ADDR": "1.2.3.4"}

    # Test concurrent requests via threads (since test_client blocks)
    results = []

    def make_request():
        res = client.get("/test", environ_base=environ)
        results.append((res.status_code, res.json))

    t1 = threading.Thread(target=make_request)
    t2 = threading.Thread(target=make_request)

    t1.start()
    time.sleep(0.05) # ensure t1 acquires first
    t2.start()

    t1.join()
    t2.join()

    # One should succeed (200), one should fail (429 or 503)
    status_codes = [r[0] for r in results]
    assert 200 in status_codes
    assert 429 in status_codes or 503 in status_codes

    # Ensure it's correctly mapped (429 if identity_limit, 503 if queue_full)
    for code, data in results:
        if code != 200:
            assert "error" in data
            assert data["reason"] in ["identity_limit", "queue_full"]
