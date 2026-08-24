"""AST-based scanner for SQL injection-prone string building.
"""

import ast
import re

from .common import walk_files

SIMPLE_SQL_RE_SOURCE = (
    r"(select\s.*from\s|"
    r"delete\s+from\s|"
    r"insert\s+into\s.*values[\s(]|"
    r"update\s.*set\s)"
)

SIMPLE_SQL_RE = re.compile(SIMPLE_SQL_RE_SOURCE, re.IGNORECASE | re.DOTALL)


class SQLScanner(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_JoinedStr(self, node):
        full_text = "".join(
            c.value
            for c in node.values
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        )
        if SIMPLE_SQL_RE.search(full_text):
            self.issues.append((node.lineno, f"f-string 사용: {full_text}"))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            if SIMPLE_SQL_RE.search(node.left.value):
                self.issues.append((node.lineno, f"연산자 결합: {node.left.value}"))
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(
                node.func.value.value, str
            ):
                if SIMPLE_SQL_RE.search(node.func.value.value):
                    self.issues.append(
                        (node.lineno, f".format() 사용: {node.func.value.value}")
                    )
        self.generic_visit(node)


def scan_file(filepath):
    """Scan a single .py file. Returns (issues, warning_message_or_None)."""
    if not filepath.endswith(".py"):
        return [], None

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source_code = f.read()
    except Exception:
        return [], f"파일을 열 수 없습니다: {filepath}"

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return [], f"파이썬 문법 오류로 건너뜁니다: {filepath}"

    scanner = SQLScanner()
    scanner.visit(tree)
    return scanner.issues, None


def scan(path, exclude=None):
    """Scan a file or directory tree.

    Returns a dict: {filepath: [(line, msg), ...]} for files with findings,
    plus a separate list of non-fatal warnings encountered along the way.
    """
    exclude = exclude or set()
    results = {}
    warnings = []

    for filepath in walk_files(path, exclude):
        issues, warning = scan_file(filepath)
        if warning:
            warnings.append(warning)
        if issues:
            results[filepath] = issues

    return results, warnings
