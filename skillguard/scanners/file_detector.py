import ast
from skillguard.scanners.python_scanner import BaseDetector
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA

class FileDetector(BaseDetector):
    """
    Detects filesystem APIs: open(), pathlib.Path, os.walk, glob.glob.
    """
    def visit_Call(self, node: ast.Call):
        resolved_name = self.resolve_attribute(node.func)
        
        # Check for matching filesystem calls
        if resolved_name in {"open", "pathlib.Path", "os.walk", "glob.glob"}:
            # Handle open vs open() mapping in RULE_METADATA
            meta_key = "open()" if resolved_name == "open" else resolved_name
            meta = RULE_METADATA[meta_key]
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
