import sys

new_handler = (
    "  // -- Flow 3 Action: Launch Run (Compose Mission) --\n"
    "  const handleLaunchRun = async (newRunProps: Partial<ActiveRunData>) => {\n"
    "    const rawObjective = (newRunProps.objective ?? '\"New Mission\"')\n"
    "      .replace(/^\"|\"$/g, '').trim();\n"
    "    const maxSteps = newRunProps.maxSteps ?? 50;\n"
    "    const computeCap = newRunProps.computeCap ?? 10.0;\n"
    "\n"
    "    if (backendOnline) {\n"
    "      try {\n"
    "        showToast('Launching mission on AgentGuard backend...');\n"
    "        const result = await createRun(rawObjective, {\n"
    "          maxSteps,\n"
    "          maxCostUsd: computeCap > 0 ? computeCap : undefined,\n"
    "          humanAvailable: true,\n"
    "        });\n"
    "        showToast(`Mission launched: ${result.run_id}`);\n"
    "        setCurrentTab('run-monitor');\n"
    "        setTimeout(async () => {\n"
    "          await fetchRuns();\n"
    "          setSelectedRunId(result.run_id);\n"
    "        }, 800);\n"
    "        return;\n"
    "      } catch (err: unknown) {\n"
    "        showToast(`Backend launch failed: ${err instanceof Error ? err.message : 'Unknown'}. Using local simulation.`);\n"
    "      }\n"
    "    }\n"
    "\n"
    "    // Fallback: local simulation\n"
    "    const newId = `run-${Math.floor(1000 + Math.random() * 9000)}-audit`;\n"
    "    const fullNewRun: ActiveRunData = {\n"
    "      id: newId,\n"
    "      name: newId,\n"
    "      objective: newRunProps.objective || '\"New Autonomous Mission\"',\n"
    "      objectiveDescription:\n"
    "        newRunProps.objectiveDescription || 'Initialized in staging-vpc-alpha with strict interlocks.',\n"
    "      status: 'RUNNING',\n"
    "      agentId: 'agent-swarm-501',\n"
    "      startedTimeAgo: 'Started just now',\n"
    "      model: newRunProps.model || 'claude-3-5-sonnet',\n"
    "      pipeline: 'security-audit-pipeline',\n"
    "      environment: newRunProps.environment || 'staging-vpc-alpha',\n"
    "      stepsTaken: 1,\n"
    "      maxSteps,\n"
    "      computeCost: 0.12,\n"
    "      computeCap,\n"
    "      tokensProcessed: 1850,\n"
    "      runtimeFormatted: '0m 12s',\n"
    "      avgLatencyMs: 650,\n"
    "      latencyCeilingMs: 1200,\n"
    "      interventionCount: 0,\n"
    "      steps: [\n"
    "        {\n"
    "          stepNumber: 1,\n"
    "          id: `stp_${newId}_01`,\n"
    "          type: 'ALLOW',\n"
    "          title: 'Step 1: Swarm Pod Handshake & Role Assumption',\n"
    "          timeAgo: 'Just now',\n"
    "          reasoning: 'Verified mTLS connection to staging VPC gateway and initialized telemetry channel.'\n"
    "        }\n"
    "      ]\n"
    "    };\n"
    "    setRuns((prev) => [fullNewRun, ...prev]);\n"
    "    setSelectedRunId(newId);\n"
    "    setCurrentTab('run-monitor');\n"
    "    showToast(`Launched (local simulation): ${newId}`);\n"
    "  };"
)

with open('src/App.tsx', 'r', encoding='utf-8') as f:
    content = f.read()

old_start = content.find('  // Actions for New Run (Compose Mission)')
old_end = content.find('\n  };\n', old_start) + 5

if old_start == -1:
    print("ERROR: could not find anchor text")
    sys.exit(1)

new_content = content[:old_start] + new_handler + content[old_end:]

with open('src/App.tsx', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"Done. Replaced chars {old_start}:{old_end}. New file size: {len(new_content)}")
