import ast
from pathlib import Path
from typing import List
from skillguard.models.finding import Finding

class BaseDetector(ast.NodeVisitor):
    """
    Base AST Visitor that tracks module imports, aliases, and resolves names/attributes
    to their fully qualified module paths.
    """
    def __init__(self, file_path: Path, project_root: Path):
        self.file_path = file_path
        self.project_root = project_root
        try:
            self.relative_path = str(file_path.relative_to(project_root)).replace("\\", "/")
        except ValueError:
            self.relative_path = str(file_path).replace("\\", "/")
        self.findings: List[Finding] = []
        self.imports = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    self.imports[f"star:{node.module}"] = True
                else:
                    local_name = alias.asname or alias.name
                    self.imports[local_name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def resolve_name(self, name: str) -> str:
        if name in self.imports:
            return self.imports[name]
        
        # Check star imports
        for key in self.imports:
            if key.startswith("star:"):
                module = key.split(":", 1)[1]
                if module == "subprocess" and name in {"Popen", "run", "call"}:
                    return f"subprocess.{name}"
                elif module == "os" and name in {"system", "walk", "getenv", "environ"}:
                    return f"os.{name}"
                elif module == "glob" and name in {"glob"}:
                    return f"glob.{name}"
                elif module == "pathlib" and name in {"Path"}:
                    return f"pathlib.{name}"
                elif module == "requests" and name in {"get", "post", "put", "delete"}:
                    return f"requests.{name}"
        return name

    def resolve_attribute(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id)
        elif isinstance(node, ast.Attribute):
            value_str = self.resolve_attribute(node.value)
            if value_str:
                return f"{value_str}.{node.attr}"
            return node.attr
        return ""

def scan_file(file_path: Path, project_root: Path) -> List[Finding]:
    """
    Parse a python file into an AST and run all detectors on it.
    """
    # Import detectors locally to avoid circular dependencies
    from skillguard.scanners.command_detector import CommandDetector
    from skillguard.scanners.file_detector import FileDetector
    from skillguard.scanners.network_detector import NetworkDetector
    from skillguard.scanners.secret_detector import SecretDetector

    findings: List[Finding] = []
    
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except Exception as e:
        # If parsing fails, we could log it or register it as a parsing issue.
        # For security scan, we return empty list or custom log.
        return []

    detectors = [
        CommandDetector(file_path, project_root),
        FileDetector(file_path, project_root),
        NetworkDetector(file_path, project_root),
        SecretDetector(file_path, project_root),
    ]

    for detector in detectors:
        detector.visit(tree)
        findings.extend(detector.findings)

    return findings
