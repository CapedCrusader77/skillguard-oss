import ast
from skillguard.scanners.python_scanner import BaseDetector
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA

class NetworkDetector(BaseDetector):
    """
    Detects outbound network requests: requests.get/post/put/delete, httpx.*, urllib.*, socket.*.
    """
    def visit_Call(self, node: ast.Call):
        resolved_name = self.resolve_attribute(node.func)
        
        # Check exact requests methods
        if resolved_name in {"requests.get", "requests.post", "requests.put", "requests.delete"}:
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
            
        # Check for httpx calls
        elif resolved_name.startswith("httpx.") or resolved_name == "httpx":
            meta = RULE_METADATA["httpx"]
            finding = Finding(
                id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                file=self.relative_path,
                line=node.lineno,
                message=f"httpx call detected: {resolved_name}"
            )
            self.findings.append(finding)
            
        # Check for urllib calls
        elif resolved_name.startswith("urllib.") or resolved_name == "urllib":
            meta = RULE_METADATA["urllib"]
            finding = Finding(
                id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                file=self.relative_path,
                line=node.lineno,
                message=f"urllib call detected: {resolved_name}"
            )
            self.findings.append(finding)
            
        # Check for socket calls
        elif resolved_name.startswith("socket.") or resolved_name == "socket":
            meta = RULE_METADATA["socket"]
            finding = Finding(
                id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                file=self.relative_path,
                line=node.lineno,
                message=f"socket connection detected: {resolved_name}"
            )
            self.findings.append(finding)
            
        self.generic_visit(node)
