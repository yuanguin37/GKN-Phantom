#!/usr/bin/env python3
"""Token-bucket rate limiter for the GKN-Phantom Penetration Testing Skill.

Gates every network-producing call across the toolkit (quick_combat probes,
deep-dive, CN probes, crawling, JS fetch, injection testing).
Default 3 req/sec with a bounded burst queue. Over-limit requests are QUEUED
(never dropped, never crash).

Importable:
    from rate_limiter import RateLimiter
    rl = RateLimiter(rps=3, burst=5)
    rl.acquire()   # blocks until a token is available

CLI (drain test):
    python rate_limiter.py --rps 3 --burst 5 --count 10

Thread-safe. FIFO (head-of-line) fairness: waiters are granted in arrival
order. A waiter that times out or errors is removed from the queue, so a dead
waiter can never block the pipeline.
"""

from __future__ import annotations

import argparse
import threading
import time


class RateLimiter:
    """Token-bucket limiter with a bounded wait queue.

    Tokens refill continuously at `rps` per second up to `burst` tokens.
    acquire() blocks until a token is granted. If the wait queue exceeds
    `max_queue`, acquire() raises QueueFullError instead of blocking forever
    (the caller should log and skip, never crash the run).
    """

    def __init__(self, rps: float = 3.0, burst: int = 5, max_queue: int = 100):
        if rps <= 0:
            raise ValueError("rps must be > 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")
        self.rps = float(rps)
        self.burst = int(burst)
        self.max_queue = int(max_queue)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._waiters: list[int] = []  # FIFO ticket numbers
        self._next_ticket = 0

    def _refill(self) -> None:
        # Caller must hold self._lock.
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.burst, self._tokens + elapsed * self.rps)
        self._last = now

    def acquire(self, timeout: float | None = None) -> float:
        """Block until a token is available. Return wait time in seconds.

        Raises QueueFullError if the wait queue is full, TimeoutError if
        `timeout` elapses first. Either way the caller's slot is released.
        """
        started = time.monotonic()
        deadline = (started + timeout) if timeout is not None else None
        with self._cond:
            if len(self._waiters) >= self.max_queue:
                raise QueueFullError(
                    f"rate limiter wait queue full ({self.max_queue}); request rejected"
                )
            ticket = self._next_ticket
            self._next_ticket += 1
            self._waiters.append(ticket)
            try:
                while True:
                    self._refill()
                    if self._waiters and self._waiters[0] == ticket and self._tokens >= 1.0:
                        self._tokens -= 1.0
                        self._waiters.pop(0)
                        self._cond.notify_all()
                        return time.monotonic() - started
                    if self._tokens >= 1.0:
                        wait = 0.0  # tokens exist; waiting for our FIFO turn
                    else:
                        wait = (1.0 - self._tokens) / self.rps
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("rate limiter acquire timed out")
                        wait = min(wait, remaining)
                    self._cond.wait(wait if wait > 0 else 0.05)
            except BaseException:
                if ticket in self._waiters:
                    self._waiters.remove(ticket)
                    self._cond.notify_all()
                raise

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return len(self._waiters)


class QueueFullError(RuntimeError):
    pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Rate limiter drain test")
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--burst", type=int, default=5)
    ap.add_argument("--count", type=int, default=10)
    args = ap.parse_args()

    rl = RateLimiter(rps=args.rps, burst=args.burst)
    for i in range(args.count):
        t0 = time.monotonic()
        rl.acquire()
        print(f"req {i + 1:02d} granted at +{time.monotonic() - t0:.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
