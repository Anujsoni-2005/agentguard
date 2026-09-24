import os
import yaml
from typing import List, Dict
from pydantic import ValidationError
from agentguard.eval.models import ScenarioSpec

def load_scenarios(scenarios_dir: str) -> List[ScenarioSpec]:
    scenarios = []
    
    if not os.path.exists(scenarios_dir):
        return scenarios
        
    for filename in os.listdir(scenarios_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            filepath = os.path.join(scenarios_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                try:
                    data = yaml.safe_load(f)
                    if not data:
                        continue
                    scenario = ScenarioSpec(**data)
                    scenarios.append(scenario)
                except ValidationError as e:
                    # Provide a clear error naming the file and field on failure
                    raise ValueError(f"Validation error in scenario file '{filepath}':\n{e}")
                except Exception as e:
                    raise ValueError(f"Failed to load scenario file '{filepath}': {e}")
                    
    return scenarios
