from abc import ABC, abstractmethod

class BaseProvider(ABC):
    @abstractmethod
    def analyze(self, claimed_purpose: str, observed_capabilities: dict) -> dict:
        """
        Analyze a repository's claimed purpose against its observed capabilities using LLMs.
        Returns a dict:
        {
            "assessment": list,      # List of strings/messages
            "trust_impact": int,     # Deduction (negative int or 0)
            "verdict": str           # e.g. "REVIEW REQUIRED"
        }
        """
        pass

    def make_prompt(self, claimed_purpose: str, observed_capabilities: dict) -> str:
        capabilities_str = "\n".join(f"- {k}: {'Yes' if v else 'No'}" for k, v in observed_capabilities.items() if v)
        if not capabilities_str:
            capabilities_str = "- None"
            
        return f"""You are a Principal AI Security Researcher.

Analyze whether the following repository's observed capabilities match its claimed purpose:

Claimed Purpose:
{claimed_purpose}

Observed Capabilities:
{capabilities_str}

Evaluate the following:
1. Are the capabilities expected for this type of tool?
2. Are any capabilities suspicious or excessive?
3. Does the behavior exceed the claimed functionality?
4. Provide a trust explanation.

Return a JSON object containing exactly the following keys:
- "assessment": A list of strings explaining why any unexpected capabilities are present or why capabilities exceed stated functionality (e.g. ["Filesystem access is not expected for a weather service.", "Command execution capability exceeds stated functionality."]). If everything is expected, return an empty list.
- "trust_impact": An integer score deduction (a negative value or 0, e.g. -25, -50). If there are suspicious or excessive capabilities, provide a negative deduction. If everything matches/is safe, return 0.
- "verdict": A string verdict. Must be one of: "SAFE", "REVIEW REQUIRED", "DANGEROUS".

Do not return any markdown formatting (like ```json) or any conversational text around the JSON object. Return raw JSON only."""
