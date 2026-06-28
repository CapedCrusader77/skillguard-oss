import json
from pathlib import Path
from skillguard.models.report import Report

def write_report_json(report: Report, output_path: str = "report.json") -> Path:
    """
    Serializes the Report model to JSON and writes it to the specified output path.
    """
    path = Path(output_path).resolve()
    
    # We use model_dump to convert the Pydantic model to a dict, serializable to JSON
    report_dict = report.model_dump()
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)
        
    return path
