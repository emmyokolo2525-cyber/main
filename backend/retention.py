import logging
import threading
import time

from config import load_config
from db import purge_expired_events
from metrics import collector as metrics_collector
from logging_utils import log_structured

LOGGER = logging.getLogger("harpocrates.retention")

class RetentionWorker:
    def __init__(self, interval_seconds: int = 3600):
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="RetentionWorker")
        self._thread.start()
        log_structured(LOGGER, logging.INFO, {"event": "retention_worker_started", "interval_seconds": self.interval_seconds})

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log_structured(LOGGER, logging.INFO, {"event": "retention_worker_stopped"})

    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._purge()
            except Exception as e:
                log_structured(LOGGER, logging.ERROR, {"event": "retention_worker_error", "error": str(e)})
            
            # Wait for interval or stop event
            self._stop_event.wait(self.interval_seconds)

    def _purge(self):
        while True:
            receipts = purge_expired_events(batch_size=100)
            num_deleted = len(receipts)
            if num_deleted > 0:
                log_structured(LOGGER, logging.INFO, {"event": "retention_worker_purged", "count": num_deleted})
                for r in receipts:
                    metrics_collector.record_deleted_event()
            if num_deleted < 100:
                break

_worker: RetentionWorker | None = None

def init_retention_worker():
    global _worker
    config = load_config()
    if config.retention_worker_enabled:
        _worker = RetentionWorker(interval_seconds=config.retention_interval_seconds)
        _worker.start()

def stop_retention_worker():
    global _worker
    if _worker:
        _worker.stop()
        _worker = None
