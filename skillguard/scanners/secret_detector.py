import ast
from skillguard.scanners.python_scanner import BaseDetector
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA

class SecretDetector(BaseDetector):
    """
    Detects secret access APIs: os.getenv and os.environ.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._flagged_lines = set()

    def _add_environ_finding(self, lineno: int):
        # Deduplicate os.environ findings per line to avoid noise
        if lineno in self._flagged_lines:
            return
        self._flagged_lines.add(lineno)
        
        meta = RULE_METADATA["os.environ"]
        finding = Finding(
            id=meta["id"],
            severity=meta["severity"],
            category=meta["category"],
            file=self.relative_path,
            line=lineno,
            message=meta["message"]
        )
        self.findings.append(finding)

    def visit_Call(self, node: ast.Call):
        resolved_name = self.resolve_attribute(node.func)
        
        if resolved_name == "os.getenv":
            meta = RULE_METADATA["os.getenv"]
            finding = Finding(
                id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                file=self.relative_path,
                line=node.lineno,
                message=meta["message"]
            )
            self.findings.append(finding)
            
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        resolved_name = self.resolve_attribute(node)
        if resolved_name == "os.environ":
            self._add_environ_finding(node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        resolved_name = self.resolve_name(node.id)
        if resolved_name == "os.environ":
            self._add_environ_finding(node.lineno)
        self.generic_visit(node)
