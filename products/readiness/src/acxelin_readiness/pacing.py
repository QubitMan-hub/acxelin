"""Pacing of live probes. One endpoint is graded with about 25 connections, so by default each host:port gets at most RATE new
connections in any second and one connection at a time. Nothing paces a probe unless a pacer is in use (`using`), which is how
--aggressive keeps the old behaviour."""
import contextlib
import contextvars
import math
import threading
import time
from collections import Counter, deque
from typing import NamedTuple

TICK = 0.25  # longest sleep, so a cancel set from outside is noticed
SLACK = 0.05  # a connection is stamped when it starts and a server sees it a little later: keep a second a second
WAIT_LIMIT = 300.0  # seconds one endpoint may wait for its turn before it is given up on


class Cancelled(Exception):
    pass


class GaveUp(Exception):
    pass


class Profile(NamedTuple):
    rate: float = 2
    workers: int = 4


GENTLE = Profile()
AGGRESSIVE = Profile(0, 16)


def profile(rate=None, workers=None, aggressive=False):
    """Settings from a command line, a settings file or a console request; ValueError when one is nonsense."""
    base = AGGRESSIVE if aggressive else GENTLE
    if rate is not None and (isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate < 0):
        raise ValueError("rate is connections a second to one host: 0 or more, 0 for no limit")
    if workers is not None and (isinstance(workers, bool) or not isinstance(workers, int) or workers < 1):
        raise ValueError("workers is how many endpoints are probed at once: 1 or more")
    return Profile(base.rate if rate is None else rate, base.workers if workers is None else workers)


class Pacer:
    def __init__(self, rate=GENTLE.rate, cancel=None, wait_limit=WAIT_LIMIT):
        self.rate, self.wait_limit = rate, wait_limit
        self.size = max(1, math.ceil(rate)) if rate else 0
        self.window = self.size / rate + SLACK if rate else 0
        self.cancel = cancel or threading.Event()
        self.cond = threading.Condition()
        self.starts, self.busy, self.opened = {}, set(), Counter()

    def stop(self):
        with self.cond:
            self.cancel.set()
            self.cond.notify_all()

    @contextlib.contextmanager
    def slot(self, host, port, waited):
        """Hold the right to open one connection to host:port. `waited` ([seconds]) is the endpoint's time spent waiting so far."""
        key = f"{host}:{port}" if ":" not in host else f"[{host}]:{port}"
        if self.rate:
            self._enter(key, waited)
        else:
            with self.cond:
                self.opened[key] += 1
        try:
            yield
        finally:
            if self.rate:
                with self.cond:
                    self.busy.discard(key)
                    self.cond.notify_all()

    def _enter(self, key, waited):
        began = time.monotonic()
        with self.cond:
            starts = self.starts.setdefault(key, deque())
            while True:
                now = time.monotonic()
                if self.cancel.is_set():
                    raise Cancelled("the scan was cancelled")
                while starts and now - starts[0] >= self.window:
                    starts.popleft()
                if key not in self.busy and len(starts) < self.size:
                    break
                if waited[0] + now - began > self.wait_limit:
                    waited[0] += now - began
                    raise GaveUp(f"gave up after waiting {self.wait_limit:g} seconds for its turn on {key}: too many endpoints on one host for this rate")
                due = TICK if key in self.busy else starts[0] + self.window - now
                self.cond.wait(min(max(due, 0.001), TICK))
            waited[0] += time.monotonic() - began
            starts.append(now)
            self.busy.add(key)
            self.opened[key] += 1

    def summary(self):
        if not self.opened:
            return ""
        total, top = sum(self.opened.values()), self.opened.most_common(10)
        more = len(self.opened) - len(top)
        return (f"opened {total} connection{'s' * (total != 1)}: " + ", ".join(f"{k} {n}" for k, n in top) + (f" and {more} more hosts" if more else ""))


_current = contextvars.ContextVar("acxelin_readiness_pacer", default=None)


@contextlib.contextmanager
def using(pacer):
    """Pace the probes made in this thread, as one endpoint's: the wait limit counts from here."""
    token = _current.set((pacer, [0.0]))
    try:
        yield pacer
    finally:
        _current.reset(token)


def slot(host, port):
    """Around every connection a probe opens (opening, talking, closing); nothing when no pacer is in use."""
    now = _current.get()
    return now[0].slot(host, port, now[1]) if now else contextlib.nullcontext()


def announce(pacer):
    """The line printed before a live scan starts."""
    if not pacer.rate:
        return "probing live endpoints without pacing (--aggressive, or a rate of 0)"
    rate = f"{pacer.rate:g}"
    return (f"pacing live probes: {'at most' if float(pacer.rate).is_integer() else 'about'} {rate} connection{'s' * (pacer.rate != 1)} a second to any one host and port; "
            "--aggressive removes the limit")
