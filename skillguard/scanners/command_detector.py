import ast
from skillguard.scanners.python_scanner import BaseDetector
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA

class CommandDetector(BaseDetector):
    """
    Detects command execution functions: subprocess.Popen, subprocess.run,
    subprocess.call, os.system, and the shell=True argument.
    """
    def visit_Call(self, node: ast.Call):
        resolved_name = self.resolve_attribute(node.func)
        
        # Check for subprocess or os.system calls
        if resolved_name in {"subprocess.Popen", "subprocess.run", "subprocess.call", "os.system"}:
            meta = RULE_METADATA[resolved_name]
            finding = Finding(
                id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                file=self.relative_path,
                line=node.lineno,
                message=meta["message"]
            )
            self.findings.append(finding)
            
        # Check for shell=True keyword argument
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                meta = RULE_METADATA["shell=True"]
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
