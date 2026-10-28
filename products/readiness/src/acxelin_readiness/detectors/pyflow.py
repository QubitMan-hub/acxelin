"""What the Python syntax tree proves about values and reachability, across the project. Nothing is imported or executed.

Values: module constants (also through imports and re-exports), class attributes (`self.ALGO`), dictionary entries
(`CONFIG["hash"]`), and the values a function's parameters receive from its callers or defaults. A parameter with several
possible values is tried with each; one that cannot be resolved stays unresolved, never guessed.

Facts: lines inside code that can never run (`if False:`, after `return`), and local definitions that only borrow an
algorithm's name (`def md5(x): return x`), which the names detector would otherwise count.
"""
import ast
import builtins
import itertools
from collections import defaultdict

from . import iter_files, rel, read

MAX_DEPTH = 4
MAX_VALUES = 8
MAX_BINDINGS = 8
BUILTINS = set(dir(builtins))
BITS = (ast.BitXor, ast.BitAnd, ast.BitOr, ast.LShift, ast.RShift, ast.Invert)


def module_name(path):
    return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")


def literal(e):
    if isinstance(e, ast.Constant) and isinstance(e.value, (str, int)) and not isinstance(e.value, bool):
        return e.value
    if isinstance(e, ast.Dict) and e.keys and all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in e.keys):
        d = {k.value: literal(v) for k, v in zip(e.keys, e.values)}
        return {k: v for k, v in d.items() if v is not None} or None
    return None


def key(v):
    return repr(v)


class Def:
    __slots__ = ("module", "qual", "cls", "node", "params", "defaults", "callers")

    def __init__(self, module, qual, cls, node):
        a = node.args
        self.module, self.qual, self.cls, self.node, self.callers = module, qual, cls, node, []
        self.params = [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs]
        positional = a.posonlyargs + a.args
        self.defaults = {p.arg: d for p, d in zip(positional[len(positional) - len(a.defaults):], a.defaults)}
        self.defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})

    @property
    def method(self):
        return self.cls is not None and self.params[:1] in (["self"], ["cls"])


class Module:
    def __init__(self, path, package, tree):
        self.path, self.name = path, module_name(path)
        self.consts, self.classes, self.imports, self.defs, self.calls, self.where = {}, defaultdict(dict), {}, {}, [], {}
        self.stores, self.attr_stores = defaultdict(int), set()
        self.base = self.name.split(".") if package else self.name.split(".")[:-1]
        self.assigns(tree.body, self.consts, None)
        self.walk(tree.body, None)

    def visit(self, st, d):
        for node in ast.walk(st):
            if isinstance(node, ast.Call):
                self.calls.append((d, node))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.stores[node.id] += 1
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                self.attr_stores.add(node.attr)
            elif isinstance(node, ast.Import):
                for n in node.names:
                    self.imports[n.asname or n.name.split(".")[0]] = (n.name if n.asname else n.name.split(".")[0], None)
            elif isinstance(node, ast.ImportFrom):
                parts = self.base[:len(self.base) - node.level + 1] if node.level else []
                target = ".".join(parts + ([node.module] if node.module else []))
                for n in node.names:
                    self.imports[n.asname or n.name] = (target, n.name)

    def assigns(self, body, into, cls):
        for st in body:
            targets = st.targets if isinstance(st, ast.Assign) else [st.target] if isinstance(st, ast.AnnAssign) and st.value else []
            v = literal(st.value) if targets else None
            for t in targets:
                if isinstance(t, ast.Name):
                    into[t.id] = None if v is None or t.id in into and into[t.id] != v else v
                    self.where[cls, t.id] = st.lineno

    def walk(self, body, cls):
        for st in body:
            if isinstance(st, ast.ClassDef) and cls is None:
                self.assigns(st.body, self.classes[st.name], st.name)
                self.walk(st.body, st.name)
                continue
            d = None
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                d = self.defs[f"{cls}.{st.name}" if cls else st.name] = Def(self, f"{cls}.{st.name}" if cls else st.name, cls, st)
            self.visit(st, d)


class Index:
    """One pass over the project's Python files; keeps only names, constants and call sites."""

    def __init__(self, root, scope=False, parse=ast.parse):
        self.modules, self.by_method, self.memo, self.used = {}, defaultdict(list), {}, {}
        for p in iter_files(root, scope):
            if p.suffix.lower() != ".py":
                continue
            text = read(p)
            if text is None:
                continue
            path = rel(root, p)
            try:
                tree = parse(text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):  # MemoryError: the parser's own stack limit
                continue
            try:
                self.modules[path] = Module(path, path.endswith("__init__.py"), tree)
            except RecursionError:
                continue
        self.by_name = {m.name: m for m in self.modules.values()}
        for m in self.modules.values():
            for d in m.defs.values():
                if d.cls:
                    self.by_method[d.node.name].append(d)
        for m in self.modules.values():
            for caller, call in m.calls:
                d, bound = self.callee(m, caller, call.func)
                if d is not None:
                    d.callers.append((m, caller, call, bound))

    def module(self, target):
        if target in self.by_name:
            return self.by_name[target]
        ends = [m for n, m in self.by_name.items() if target.endswith("." + n)]
        return ends[0] if len(ends) == 1 else None

    def imported(self, m, name, hops=3):
        """(module, attribute) a local name finally refers to, following re-exports."""
        while hops and name in m.imports:
            target, attr = m.imports[name]
            if attr is None:
                return self.module(target), None
            nxt = self.module(target)
            if nxt is None:
                return None, None
            if attr not in nxt.imports:
                return nxt, attr
            m, name, hops = nxt, attr, hops - 1
        return None, None

    def qualified(self, m, name):
        """`quick_digest` re-exported from `from hashlib import sha1 as quick_digest` is hashlib.sha1."""
        hops = 3
        while hops and name in m.imports:
            target, attr = m.imports[name]
            nxt = self.module(target)
            if attr is None or nxt is None:
                return target + ("." + attr if attr else "")
            if attr not in nxt.imports:
                return None
            m, name, hops = nxt, attr, hops - 1
        return None

    def callee(self, m, caller, func):
        cls = caller.cls if isinstance(caller, Def) else None
        if isinstance(func, ast.Name):
            if func.id in m.defs:
                return m.defs[func.id], False
            if func.id in m.classes:
                return m.defs.get(func.id + ".__init__"), True
            tm, attr = self.imported(m, func.id)
            if tm and attr:
                return tm.defs.get(attr) or tm.defs.get(attr + ".__init__"), attr not in tm.defs
            return None, False
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            if base in ("self", "cls") and cls and f"{cls}.{func.attr}" in m.defs:
                return m.defs[f"{cls}.{func.attr}"], True
            if base in m.classes and f"{base}.{func.attr}" in m.defs:
                return m.defs[f"{base}.{func.attr}"], False
            tm, attr = self.imported(m, base)
            if tm and attr is None:
                return tm.defs.get(func.attr), False
        if isinstance(func, ast.Attribute):
            only = self.by_method.get(func.attr, [])
            if len(only) == 1:
                return only[0], True
        return None, False

    def resolve(self, m, d, e, depth=MAX_DEPTH, parameters=True, cls=None):
        """Every value `e` can be shown to hold, in module `m` inside function `d` (or class `cls`); [] when unknown."""
        v = literal(e)
        if v is not None:
            return [v]
        if depth <= 0:
            return []
        if isinstance(e, ast.Name):
            if d is not None and e.id in d.params:
                return self.parameter(d, e.id, depth - 1) if parameters else []
            if e.id in m.consts:
                return self.const(m, None, e.id) if m.stores[e.id] <= 1 else []
            if m.stores[e.id]:
                return []
            tm, attr = self.imported(m, e.id)
            return self.const(tm, None, attr) if tm and attr else []
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
            base, cls = e.value.id, d.cls if d is not None else cls
            if base in ("self", "cls") and cls:
                return self.const(m, cls, e.attr)
            if base in m.classes:
                return self.const(m, base, e.attr)
            tm, attr = self.imported(m, base)
            return self.const(tm, attr, e.attr) if tm else []
        if isinstance(e, ast.Subscript):
            k = literal(e.slice)
            if isinstance(k, (str, int)):
                return [x[k] for x in self.resolve(m, d, e.value, depth - 1, parameters, cls) if isinstance(x, dict) and k in x]
        return []

    def const(self, m, cls, name):
        """A constant's value, remembering where it was defined: that definition then counts as used. A name bound again
        anywhere else in its module (or an attribute ever assigned at run time) is not a constant."""
        v = (m.classes.get(cls, {}) if cls else m.consts).get(name)
        if v is None or (name in m.attr_stores if cls else m.stores[name] > 1):
            return []
        if (cls, name) in m.where and isinstance(v, str):
            self.used[m.path, m.where[cls, name]] = v
        return [v]

    def parameter(self, d, name, depth):
        memo = (id(d), name, depth)
        if memo not in self.memo:
            self.memo[memo] = []
            self.memo[memo] = self._parameter(d, name, depth)
        return self.memo[memo]

    def _parameter(self, d, name, depth):
        i = d.params.index(name)
        out, seen = [], set()

        def add(vals):
            for v in vals:
                if key(v) not in seen and len(out) < MAX_VALUES:
                    seen.add(key(v))
                    out.append(v)
        default = d.defaults.get(name)
        for m, caller, call, bound in d.callers:
            pos = i - (1 if d.method and bound else 0)
            arg = next((k.value for k in call.keywords if k.arg == name), None)
            if arg is None and 0 <= pos < len(call.args) and not any(isinstance(a, ast.Starred) for a in call.args[:pos + 1]) \
                    and name not in [p.arg for p in d.node.args.kwonlyargs]:
                arg = call.args[pos]
            if arg is None and (call.keywords and any(k.arg is None for k in call.keywords)):
                continue
            if arg is not None:
                add(self.resolve(m, caller if isinstance(caller, Def) else None, arg, depth))
            elif default is not None:
                add(self.resolve(d.module, None, default, depth))
        if not d.callers and default is not None:
            add(self.resolve(d.module, None, default, depth))
        return out

    def bindings(self, d, names):
        """Parameter values to re-read `d` with: each combination the callers and defaults make possible, capped."""
        options = [(p, [v for v in self.parameter(d, p, MAX_DEPTH) if not isinstance(v, dict)]) for p in d.params if p in names]
        options = [(p, vals) for p, vals in options if vals]
        if not options:
            return []
        return [dict(zip([p for p, _ in options], combo)) for combo in itertools.islice(itertools.product(*[v for _, v in options]), MAX_BINDINGS)]


    def view(self, path):
        return View(self, path)


class View:
    """What one file's scan may ask of the index."""

    def __init__(self, index, path):
        self.index, self.module = index, index.modules.get(path)

    def value(self, e, owner):
        if self.module is None:
            return None
        vals = self.index.resolve(self.module, None, e, parameters=False, cls=owner)
        return vals[0] if len(vals) == 1 and not isinstance(vals[0], dict) else None

    def alias(self, name):
        return self.index.qualified(self.module, name) if self.module is not None else None

    def functions(self, relevant):
        """(definition, binding) pairs for the functions whose parameters reach a crypto call; `relevant(node)` names those parameters."""
        if self.module is None:
            return []
        out = []
        for d in self.module.defs.values():
            names = relevant(d.node) - {"self", "cls"}
            out += [(d, b) for b in self.index.bindings(d, names)] if names else []
        return out


def inert(node):
    """A definition that cannot be doing cryptography: no bit operations and no calls beyond Python's builtins."""
    for n in ast.walk(node):
        if isinstance(n, ast.BinOp) and isinstance(n.op, BITS) or isinstance(n, ast.AugAssign) and isinstance(n.op, BITS) \
                or isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Invert) or isinstance(n, (ast.Import, ast.ImportFrom)):
            return False
        if isinstance(n, ast.Call) and not (isinstance(n.func, ast.Name) and n.func.id in BUILTINS):
            return False
    return True


def blocks(node):
    """The statement lists directly under a node: bodies, else branches, handlers and match cases."""
    for field in ("body", "orelse", "finalbody", "handlers", "cases"):
        block = getattr(node, field, None)
        if isinstance(block, list) and block:
            yield field, block


def statements(node):
    for _, block in blocks(node):
        for st in block:
            yield st
            yield from statements(st)


def facts(tree):
    """({line: names of inert local definitions defined or called there}, {lines that can never run}). Walks statements only;
    expressions are visited just when a look-alike definition exists."""
    from .names import algos
    lines, dead = defaultdict(set), set()
    stmts = list(statements(tree))
    names = {st.name for st in stmts if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and algos(st.name) and inert(st)}
    for st in stmts if names else ():
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and st.name in names:
            lines[st.lineno].add(st.name)
    for n in ast.walk(tree) if names else ():
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in names:
            lines[n.lineno].add(n.func.id)
    for n in [tree, *stmts]:
        for field, block in blocks(n):
            if field in ("body", "orelse") and isinstance(n, (ast.If, ast.While)) and isinstance(n.test, ast.Constant):
                if bool(n.test.value) == (field == "orelse"):
                    dead.update(span(block))
                    continue
            for i, st in enumerate(block[:-1]):
                if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    dead.update(span(block[i + 1:]))
                    break
    return dict(lines), dead


def span(block):
    out = set()
    for st in block:
        out.update(range(st.lineno, (getattr(st, "end_lineno", None) or st.lineno) + 1))
    return out


def mark(detections, found):
    """Context for verification: `lookalike` on a name detection that is only a local definition's name, `unreachable` on any
    detection in code that can never run."""
    from .names import algos
    for s in detections:
        f = found.get(s.file)
        if not f:
            continue
        named, dead = f
        if s.detector in ("names", "symbols") and any(s.algo in algos(n) for n in named.get(s.line, ())):
            s.context.add("lookalike")
        if s.line in dead:
            s.context.add("unreachable")
