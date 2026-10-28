"""Bounded Python AST relationships. Never executes code or retains source/argument values."""
import ast
import json
import hashlib
import threading
from collections import OrderedDict, defaultdict, deque


LIMIT_SYMBOLS = 20_000
LIMIT_CALLS = 100_000


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else ""
    return ""


class ParseCache:
    """Bounded in-memory syntax reuse; relationships and findings are always recomputed."""
    def __init__(self, max_bytes=32_000_000, max_entries=5000):
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self.entries, self.bytes = OrderedDict(), 0
        self.lock = threading.Lock()

    def parse(self, language, source, parser):
        key = language, hashlib.sha256(source).digest()
        with self.lock:
            if key in self.entries:
                self.entries.move_to_end(key)
                return self.entries[key][0], True
        tree = parser(source)
        with self.lock:
            if len(source) <= self.max_bytes and self.max_entries > 0:
                previous = self.entries.pop(key, None)
                if previous:
                    self.bytes -= previous[1]
                self.entries[key] = tree, len(source)
                self.bytes += len(source)
                while self.bytes > self.max_bytes or len(self.entries) > self.max_entries:
                    _, (_, size) = self.entries.popitem(last=False)
                    self.bytes -= size
        return tree, False


class CodeCrawler:
    def __init__(self, cache=None):
        self.cache = cache
        self.cache_hits = self.cache_misses = 0
        self.truncated = defaultdict(lambda: defaultdict(int))
        self.symbols = []
        self.calls = []
        self.imports = []
        self.files = 0
        self.limited = False
        self.uncertain_lines = defaultdict(set)
        self.languages = defaultdict(int)
        self.skipped = defaultdict(int)
        self.coverage_files = defaultdict(list)
        self.parsers = {}
        self.aliases = []
        self.crypto_contexts = []

    def parse(self, language, source, parser):
        if self.cache is None:
            self.cache_misses += 1
            return parser(source)
        try:
            tree, hit = self.cache.parse(language, source, parser)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self.cache_misses += 1
            raise
        self.cache_hits += int(hit)
        self.cache_misses += int(not hit)
        return tree

    def parse_python(self, text):
        return self.parse("Python", text.encode("utf-8"), lambda raw: ast.parse(raw.decode("utf-8")))

    def peek_python(self, text):
        """A tree for analysis that runs before the scan proper: reads the cache, never fills it or moves its counters."""
        if self.cache is not None:
            with self.cache.lock:
                hit = self.cache.entries.get(("Python", hashlib.sha256(text.encode("utf-8")).digest()))
            if hit:
                return hit[0]
        return ast.parse(text)

    def cut(self, path, kind):
        self.limited = True
        self.truncated[path][kind] += 1

    def add_symbol(self, path, module, name, kind, line, end_line, **extra):
        if len(self.symbols) >= LIMIT_SYMBOLS:
            self.cut(path, "symbols")
            return
        self.symbols.append({"id": path + "#" + name, "file": path, "module": module, "name": name or module,
                             "kind": kind, "line": line, "end_line": end_line, **extra})

    def add_call(self, path, source, line, callee, candidate):
        if len(self.calls) >= LIMIT_CALLS:
            self.cut(path, "calls")
            return
        self.calls.append({"source": path + "#" + source, "file": path, "line": line, "callee": callee, "candidate": candidate})

    def add_import(self, path, source, module, line):
        if len(self.imports) >= LIMIT_CALLS:
            self.cut(path, "imports")
            return
        self.imports.append({"file": path, "source": path + "#" + source, "module": module, "line": line})

    def add_alias(self, family, alias, target, path):
        if len(self.aliases) >= LIMIT_CALLS:
            self.cut(path, "aliases")
            return
        self.aliases.append({"family": family, "alias": alias, "target": target})

    def gap(self, category, path):
        self.skipped[category] += 1
        if len(self.coverage_files[category]) < 1000:
            self.coverage_files[category].append(path)

    def observe_source(self, path, text, language):
        typed = {"java": "Java", "go": "Go"}.get(language) if path.endswith((".java", ".go")) else None
        if typed:
            from .crawler_typed import observe
            return self.guarded(lambda: observe(self, path, text, typed), path, typed + " (analysis depth limit)")
        if language not in {"js", "python"}:
            self.gap(language + " (no relationship adapter)", path)
        if language == "js":
            from .crawler_web import observe
            return self.guarded(lambda: observe(self, path, text), path, "Web syntax (analysis depth limit)")

    def guarded(self, work, path, category):
        """Run one file's analysis; a tree too deep to walk is rolled back and reported as a coverage gap."""
        sizes = (len(self.symbols), len(self.calls), len(self.imports), len(self.aliases), len(self.crypto_contexts), self.files, dict(self.languages))
        try:
            return work()
        except RecursionError:
            ns, nc, ni, na, nx, self.files, languages = sizes
            del self.symbols[ns:]
            del self.calls[nc:]
            del self.imports[ni:]
            del self.aliases[na:]
            del self.crypto_contexts[nx:]
            self.languages = defaultdict(int, languages)
            self.uncertain_lines.pop(path, None)
            self.gap(category, path)
            self.limited = True

    def observe(self, path, tree):
        """Called with the very AST the existing cryptographic detector uses."""
        self.guarded(lambda: self.observe_python(path, tree), path, "Python (analysis depth limit)")

    def observe_python(self, path, tree):
        self.files += 1
        self.languages["Python"] += 1
        module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        if module == "__init__":
            module = ""
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        crawler = self
        # Bindings collected per lexical scope. Reassignment/shadowing is uncertain.
        def bindings(body, params=()):
            table = defaultdict(list)
            for param in params:
                table[param].append(None)
            class Bind(ast.NodeVisitor):
                def visit_Import(self, n):
                    for a in n.names:
                        table[a.asname or a.name.split(".")[0]].append(a.name if a.asname else a.name.split(".")[0])
                def visit_ImportFrom(self, n):
                    base = n.module or ""
                    if n.level:
                        parts = package.split(".") if package else []
                        base = ".".join(parts[:len(parts) - n.level + 1] + ([base] if base else [])) if n.level <= len(parts) else ""
                    for a in n.names:
                        if a.name != "*":
                            table[a.asname or a.name].append(base + "." + a.name if base else None)
                def visit_Name(self, n):
                    if isinstance(n.ctx, (ast.Store, ast.Del)):
                        table[n.id].append(None)
                def visit_FunctionDef(self, n):
                    table[n.name].append("@" + n.name)
                visit_AsyncFunctionDef = visit_FunctionDef
                def visit_ClassDef(self, n):
                    table[n.name].append("@" + n.name)
                def visit_Lambda(self, n):
                    pass
            visitor = Bind()
            for node in body:
                visitor.visit(node)
            return {name: values[0] if len(values) == 1 else None for name, values in table.items()}

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                names = bindings(tree.body)
                for name, target in names.items():
                    if target and not target.startswith("@"):
                        crawler.add_alias("Python", module + "." + name, target, path)
                self.stack = [("", names, "module")]
                self.add("", "module", tree)
            def add(self, qual, kind, node, **extra):
                crawler.add_symbol(path, module, qual, kind, getattr(node, "lineno", 1), getattr(node, "end_lineno", 10**9), language="Python", **extra)
            def visit_FunctionDef(self, node):
                qual = ".".join(x for x in (self.stack[-1][0], node.name) if x)
                self.add(qual, "function", node, body_line=node.body[0].lineno if node.body else node.lineno)
                # Decorators/defaults execute in the defining scope, not the function.
                for n in node.decorator_list + node.args.defaults + [n for n in node.args.kw_defaults if n is not None]:
                    crawler.uncertain_lines[path].update(range(n.lineno, n.end_lineno + 1))
                    self.visit(n)
                params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                params += [a.arg for a in (node.args.vararg, node.args.kwarg) if a]
                self.stack.append((qual, bindings(node.body, params), "function"))
                for n in node.body:
                    self.visit(n)
                self.stack.pop()
            visit_AsyncFunctionDef = visit_FunctionDef
            def visit_ClassDef(self, node):
                qual = ".".join(x for x in (self.stack[-1][0], node.name) if x)
                self.add(qual, "class", node, bases=[dotted(n) for n in node.bases if dotted(n)])
                for n in node.bases + node.decorator_list:
                    self.visit(n)
                self.stack.append((qual, bindings(node.body), "class"))
                for n in node.body:
                    self.visit(n)
                self.stack.pop()
            def visit_Lambda(self, node):
                # Anonymous functions have uncertain invocation; do not attribute their calls to the enclosing workflow.
                crawler.uncertain_lines[path].update(range(node.lineno, node.end_lineno + 1))
            def visit_Import(self, node):
                for a in node.names:
                    self.record_import(node, a.name)
            def visit_ImportFrom(self, node):
                self.record_import(node, "." * node.level + (node.module or ""))
            def record_import(self, node, name):
                crawler.add_import(path, self.stack[-1][0], name, node.lineno)
            def visit_Call(self, node):
                if len(crawler.calls) >= LIMIT_CALLS:
                    crawler.cut(path, "calls (including unvisited nested calls)")
                    return
                name, candidate = dotted(node.func), ""
                if name:
                    head, _, tail = name.partition(".")
                    for qual, names, kind in reversed(self.stack):
                        if kind == "class" and self.stack[-1][2] == "function":
                            continue  # class attributes are not lexical names in methods
                        if head in names:
                            bound = names[head]
                            if bound and bound.startswith("@"):
                                candidate = module + "." + ".".join(x for x in (qual, bound[1:], tail) if x)
                            elif bound:
                                candidate = bound + ("." + tail if tail else "")
                            break
                crawler.add_call(path, self.stack[-1][0], node.lineno, name or "dynamic call", candidate)
                self.generic_visit(node)
        Visitor().visit(tree)

    def finish(self, assets):
        names = defaultdict(list)
        families = {s["file"]: {"Python": "Python", "Java": "java", "Go": "go"}.get(s.get("language", "Python"), "web") for s in self.symbols}
        symbols = {s["id"]: s for s in self.symbols}
        for symbol in self.symbols:
            if symbol["kind"] == "module":
                continue
            canonical = symbol["module"] + ("." + symbol["name"] if symbol["kind"] != "module" else "")
            names[families[symbol["file"]], canonical].append(symbol["id"])
            for alias in symbol.get("aliases", []):
                names[families[symbol["file"]], symbol["module"] + "." + alias].append(symbol["id"])
            if canonical.startswith("src."):
                names[families[symbol["file"]], canonical[4:]].append(symbol["id"])
        go_tails = defaultdict(list)
        for (family, canonical), ids in names.items():
            if family == "go":
                go_tails[canonical.rsplit("/", 1)[-1]].append((canonical, ids))
        aliases = defaultdict(list)
        for alias in self.aliases:
            aliases[alias["family"], alias["alias"]].append(alias["target"])
        def resolve(family, candidate, trail=()):
            if candidate in trail:
                return []
            if len(trail) >= 20:
                self.limited = True
                return []
            matches = list(names.get((family, candidate), []))
            if family == "go" and not matches:
                # Go imports name the module path; files are known by folder, so match on the trailing folders.
                matches = [i for canonical, ids in go_tails.get(candidate.rsplit("/", 1)[-1], []) if candidate.endswith("/" + canonical) for i in ids]
            for target in aliases.get((family, candidate), []):
                matches.extend(resolve(family, target, trail + (candidate,)))
            return matches
        callers = defaultdict(set)
        calls = []
        for raw in self.calls:
            call = {k: v for k, v in raw.items() if k != "candidate"}
            matches = resolve(families.get(raw["file"], "Python"), raw["candidate"])
            if families.get(raw["file"]) == "web":
                matches = [m for m in matches if symbols[m]["file"] == raw["file"] or symbols[m].get("exported")]
            call["reference"] = raw["candidate"] or None
            call["target"] = matches[0] if len(matches) == 1 else None
            call["confidence"] = "observed static reference" if call["target"] else "unresolved; inspect dispatch"
            if call["target"]:
                callers[call["target"]].add(call["source"])
            calls.append(call)
        by_file = defaultdict(list)
        for symbol in self.symbols:
            if symbol["kind"] == "function":
                by_file[symbol["file"]].append(symbol)
        for asset in assets:
            contexts = [c for c in self.crypto_contexts if asset.algo in c['algorithms'] and
                        any(s.file == c['file'] and c['line'] <= s.line <= c['end_line'] for s in asset.detections)]
            if contexts:
                asset.params['hybrid_context'] = contexts
                asset.why += ". Some uses pass a classical component alongside ML-KEM to a combiner; review those compositions separately from standalone uses. This is not a verdict on the hybrid's security."
            owners = set()
            for detection in asset.detections:
                if detection.evidence == "import" or detection.verdict != "accepted":
                    continue
                enclosing = [s for s in by_file[detection.file] if s.get("body_line", s["line"]) <= detection.line <= s["end_line"] and detection.line not in self.uncertain_lines[detection.file]]
                if enclosing:
                    owners.add(min(enclosing, key=lambda s: s["end_line"] - s["line"])["id"])
            affected, pending = set(owners), deque(sorted(owners))
            while pending and len(affected) < 500:
                for caller in sorted(callers[pending.popleft()]):
                    if caller not in affected:
                        affected.add(caller)
                        pending.append(caller)
                        if len(affected) >= 500:
                            break
            if owners:
                asset.params["code_impact"] = {"functions": sorted(owners), "callers": sorted(affected - owners),
                                             "modules": sorted({symbols[s]["module"] for s in affected if s in symbols}),
                                             "limited": bool(pending), "basis": "static references; runtime reachability and business ownership are not established"}
        return {"version": 1, "language": ", ".join(sorted(self.languages)) or "Python", "languages": dict(self.languages), "skipped": dict(self.skipped), "files_analyzed": self.files, "symbols": self.symbols,
                "calls": calls, "imports": self.imports, "aliases": self.aliases, "limited": self.limited,
                "truncated_files": dict(self.truncated), "coverage_files": dict(self.coverage_files),
                "coverage_file_list_limit": 1000,
                "incremental": {"reused_syntax": self.cache_hits, "parsed_syntax": self.cache_misses, "basis": "Content-hash syntax cache; all findings and cross-file relationships recomputed"},
                "limitations": ["Python AST and optional JavaScript/TypeScript, Java and Go syntax trees; other languages retain crypto detectors without call graphs.",
                                "Dynamic dispatch, wildcard imports, callbacks and runtime reassignment require manual review.",
                                "No source snippets, argument values, docstrings or runtime execution are included."]}


def impact_property(asset):
    value = asset.params.get("code_impact")
    return json.dumps(value, separators=(",", ":")) if value else None
