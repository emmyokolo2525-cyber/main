import concurrent.futures
import threading
import time
from typing import Callable, NamedTuple, Dict, List

class ProbeResult(NamedTuple):
    ok: bool
    status: str
    timestamp: float

class Dependency(NamedTuple):
    name: str
    check_fn: Callable[[], bool]
    critical: bool

class ReadinessManager:
    """
    Manages bounded dependency health checks.
    Runs probes in parallel with a strict timeout and caches results.
    """
    def __init__(self, timeout_seconds: float = 1.0, cache_ttl_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self.deps: List[Dependency] = []
        self.cache: Dict[str, ProbeResult] = {}
        self._lock = threading.Lock()

    def add_dependency(self, name: str, check_fn: Callable[[], bool], critical: bool = True):
        self.deps.append(Dependency(name, check_fn, critical))
        # Initialize cache
        self.cache[name] = ProbeResult(False, "initializing", 0.0)

    def _run_probe(self, dep: Dependency) -> ProbeResult:
        try:
            ok = dep.check_fn()
            status = "connected" if ok else "disconnected"
            # Special case for existing schemas
            if dep.name == "video_tools":
                status = "available" if ok else "missing"
            elif dep.name == "database":
                status = "connected" if ok else "not_configured"
            
            return ProbeResult(ok, status, time.time())
        except Exception:
            return ProbeResult(False, "error", time.time())

    def check(self) -> dict:
        now = time.time()
        to_run = []
        
        with self._lock:
            for dep in self.deps:
                cached_res = self.cache.get(dep.name)
                # If cache is older than TTL or we are initializing, run the probe.
                if not cached_res or now - cached_res.timestamp > self.cache_ttl_seconds:
                    to_run.append(dep)
        
        if to_run:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(to_run)))
            try:
                future_to_dep = {executor.submit(self._run_probe, dep): dep for dep in to_run}
                done, not_done = concurrent.futures.wait(
                    future_to_dep.keys(), timeout=self.timeout_seconds
                )
                
                with self._lock:
                    for future in done:
                        dep = future_to_dep[future]
                        try:
                            self.cache[dep.name] = future.result()
                        except Exception:
                            self.cache[dep.name] = ProbeResult(False, "error", time.time())
                    
                    # Timed-out probes preserve the last known cache value.
                    # In particular, a first probe remains "initializing".
                    for future in not_done:
                        future.cancel()
            finally:
                # A context manager waits for timed-out worker threads during
                # shutdown, defeating the readiness endpoint's time bound.
                executor.shutdown(wait=False, cancel_futures=True)

        # Build response
        with self._lock:
            overall_ok = True
            response = {}
            for dep in self.deps:
                res = self.cache[dep.name]
                if dep.critical and not res.ok:
                    overall_ok = False
                
                response[dep.name] = res.status
                
            response["ok"] = overall_ok
            return response
