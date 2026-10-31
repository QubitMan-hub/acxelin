"""Command-line mechanisms the products share: prompts, output, signals, log format and option help. Each product owns its commands."""
import argparse
import getpass
import json
import logging
import signal
import sys


class JSONFormatter(logging.Formatter):
    def format(self, r):
        out = {"time": self.formatTime(r), "level": r.levelname, "logger": r.name, "message": r.getMessage()}
        if r.exc_info:
            out["exception"] = self.formatException(r.exc_info)
        return json.dumps(out)


def ask(prompt, instead):
    """A passphrase typed at the terminal; without one (a pipe, a service, CI) a clear error naming the alternative."""
    try:
        if not sys.stdin.isatty():
            raise EOFError
        return getpass.getpass(prompt).encode()
    except EOFError:
        raise ValueError(f"no terminal to type the passphrase in: {instead}") from None


def show(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=1, default=str))
    else:
        for k, v in obj.items():
            print(f"{k:>14}  {', '.join(map(str, v)) if isinstance(v, (list, tuple)) else 'none' if v is None else v}")


def positive(kind):
    def check(s):
        try:
            v = kind(s)
        except ValueError:
            v = 0
        if not 0 < v <= 36500:
            raise argparse.ArgumentTypeError(f"expected a number above 0 and at most 36500, got {s!r}")
        return v
    return check


def run_until_signal(run, stop, reload=None, log="acxelin"):
    """Run until SIGINT or SIGTERM calls `stop`. With `reload`, SIGHUP (`systemctl reload`) calls it, where the platform has one."""
    def handle(*_):
        logging.getLogger(log).info("shutting down")
        stop()
    signal.signal(signal.SIGINT, handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle)
    if reload and hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: reload())
    run()


def explain_options(p, help_by_dest):
    """Give every option that has no help of its own the shared wording for its name."""
    for a in p._actions:
        if isinstance(a, argparse._SubParsersAction):
            for c in a.choices.values():
                explain_options(c, help_by_dest)
        elif a.help is None and a.dest in help_by_dest:
            a.help = help_by_dest[a.dest]
