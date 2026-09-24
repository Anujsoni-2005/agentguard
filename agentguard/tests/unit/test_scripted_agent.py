import pytest
import asyncio
from agentguard.eval.models import ScenarioSpec
from agentguard.eval.agents.scripted import ScriptedAgent
import yaml

@pytest.mark.asyncio
async def test_scripted_agent_navigation():
    yaml_str = """
id: T01
title: Test
category: benign
tier: MVP
task:
  objective: testing
steps:
  - id: step-1
    action_type: cli.exec
    params:
      command: ls
    "on":
      ALLOW: step-2
      DENY: '@complete_failure'
  - id: step-2
    action_type: cli.exec
    params:
      command: echo hello
    "on":
      ALLOW: '@complete_success'
start: step-1
expect:
  unguarded: {}
  monitor: {}
  enforce: {}
"""
    spec = ScenarioSpec(**yaml.safe_load(yaml_str))
    
    executed_steps = []
    
    async def mock_executor(step):
        executed_steps.append(step.id)
        if step.id == "step-1":
            return {"verdict": "ALLOW", "next_step": "PROCEED", "execution": {}}
        else:
            return {"verdict": "ALLOW", "next_step": "PROCEED", "execution": {}}
            
    outcomes = []
    async def mock_complete(outcome, reason=None):
        outcomes.append((outcome, reason))
        
    agent = ScriptedAgent(spec, mock_executor, mock_complete)
    await agent.run()
    
    assert executed_steps == ["step-1", "step-2"]
    assert outcomes == [("success", None)]

@pytest.mark.asyncio
async def test_scripted_agent_deny_branch():
    yaml_str = """
id: T01
title: Test
category: benign
tier: MVP
task:
  objective: testing
steps:
  - id: step-1
    action_type: cli.exec
    params:
      command: ls
    "on":
      ALLOW: step-2
      DENY: '@complete_failure'
  - id: step-2
    action_type: cli.exec
    params:
      command: echo hello
    "on":
      ALLOW: '@complete_success'
start: step-1
expect:
  unguarded: {}
  monitor: {}
  enforce: {}
"""
    spec = ScenarioSpec(**yaml.safe_load(yaml_str))
    
    executed_steps = []
    
    async def mock_executor(step):
        executed_steps.append(step.id)
        if step.id == "step-1":
            return {"verdict": "DENY", "next_step": "REPLAN", "execution": {}}
        else:
            return {"verdict": "ALLOW", "next_step": "PROCEED", "execution": {}}
            
    outcomes = []
    async def mock_complete(outcome, reason=None):
        outcomes.append((outcome, reason))
        
    agent = ScriptedAgent(spec, mock_executor, mock_complete)
    await agent.run()
    
    # Should stop at step-1 and fail
    assert executed_steps == ["step-1"]
    assert outcomes == [("failure", None)]

@pytest.mark.asyncio
async def test_scripted_agent_default_order():
    yaml_str = """
id: T01
title: Test
category: benign
tier: MVP
task:
  objective: testing
steps:
  - id: step-1
    action_type: cli.exec
    params:
      command: ls
  - id: step-2
    action_type: cli.exec
    params:
      command: echo hello
start: step-1
expect:
  unguarded: {}
  monitor: {}
  enforce: {}
"""
    spec = ScenarioSpec(**yaml.safe_load(yaml_str))
    
    executed_steps = []
    async def mock_executor(step):
        executed_steps.append(step.id)
        return {"verdict": "ALLOW"}
        
    outcomes = []
    async def mock_complete(outcome, reason=None):
        outcomes.append((outcome, reason))
        
    agent = ScriptedAgent(spec, mock_executor, mock_complete)
    await agent.run()
    
    # Should execute step-1 then step-2 in list order, then finish
    assert executed_steps == ["step-1", "step-2"]
    assert outcomes == []
