from pathlib import Path
from typing import List
from skillguard.models.finding import Finding

analyzer_registry: List["BaseAnalyzer"] = []

class BaseAnalyzer:
    """
    Abstract base class for SkillGuard plugins.
    Each analyzer must implement the analyze method to perform scan logic.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        """
        Analyze a repository or directory and return a list of security findings.
        """
        raise NotImplementedError("Analyzers must implement analyze()")

def register_analyzer(cls):
    """
    Decorator to register a new analyzer instance into the global registry.
    """
    analyzer_registry.append(cls())
    return cls
