# Troubleshooting Guide

Common issues and solutions for Agent OS.

## Installation Issues

### "Command not found: agentos"

**Problem:** After installing, the `agentos` command isn't found.

**Solutions:**

1. **Ensure pip scripts are in PATH:**
   ```bash
   # Linux/macOS
   export PATH="$HOME/.local/bin:$PATH"
   
   # Or use Python module directly
   python -m agent_os.cli --help
   ```

2. **Reinstall with pip:**
   ```bash
   pip install --force-reinstall agent-os
   ```

3. **Check installation:**
   ```bash
   pip show agent-os
   ```

### "ModuleNotFoundError: No module named 'agent_os'"

**Problem:** Python can't find the agent_os module.

**Solutions:**

1. **Check you're in the right Python environment:**
   ```bash
   which python
   pip list | grep agent-os
   ```

2. **Install in the correct environment:**
   ```bash
   python -m pip install agent-os
   ```

### Import errors with optional dependencies

**Problem:** `ImportError: redis adapter requires 'redis' package`

**Solution:** Install the specific extra:
```bash
pip install agent-os-kernel[redis]
pip install agent-os-kernel[kafka]
pip install agent-os-kernel[full]  # All extras
```

---

## Policy Issues

### "Policy violation but I expected it to pass"

**Problem:** Code is being blocked that should be allowed.

**Solutions:**

1. **Check active policies:**
   ```bash
   agentos audit
   ```

2. **Review your policy file:**
   ```bash
   cat .agents/security.md  # or .agent-os.yaml
   ```

3. **Test with permissive mode:**
   ```python
   kernel = KernelSpace(policy="permissive")  # Logs only
   ```

4. **Add an exception:**
   ```yaml
   policies:
     - name: block_secrets
       exceptions:
         - "test_api_key"  # Allow this specific pattern
   ```

### "SIGKILL but no explanation"

**Problem:** Agent is killed but the reason isn't clear.

**Solution:** Enable verbose logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

kernel = KernelSpace(policy="strict", debug=True)
```

---

## Runtime Issues

### Agent hangs or doesn't respond

**Problem:** Agent seems stuck.

**Solutions:**

1. **Check for SIGSTOP:**
   ```python
   # Agent may be paused waiting for approval
   # Check your notification channels
   ```

2. **Add timeout:**
   ```python
   result = await asyncio.wait_for(
       kernel.execute(my_agent, task),
       timeout=30.0
   )
   ```

3. **Check rate limits:**
   ```yaml
   # Rate limits may be pausing execution
   policies:
     - name: rate_limit
       limits:
         - action: llm_call
           max_per_minute: 60
   ```

### High memory usage

**Problem:** Agent consumes too much memory.

**Solutions:**

1. **Limit response sizes:**
   ```python
   from atr.tools.safe import HttpClientTool
   
   http = HttpClientTool(max_response_size=1_000_000)  # 1MB limit
   ```

2. **Clear episodic memory:**
   ```python
   memory.clear(conversation_id)
   ```

3. **Use streaming for large responses:**
   ```python
   # Process data in chunks instead of loading all at once
   ```

---

## Message Bus Issues

### "Connection refused" for Redis/Kafka

**Problem:** Can't connect to message broker.

**Solutions:**

1. **Check broker is running:**
   ```bash
   # Redis
   redis-cli ping
   
   # Kafka
   kafka-topics.sh --list --bootstrap-server localhost:9092
   ```

2. **Verify connection string:**
   ```python
   broker = RedisBroker(url="redis://localhost:6379/0")  # Check URL
   ```

3. **Check firewall/network:**
   ```bash
   telnet localhost 6379
   ```

### Messages not being received

**Problem:** Published messages don't reach subscribers.

**Solutions:**

1. **Verify topic names match:**
   ```python
   # Publisher
   await bus.publish(Message(topic="tasks", ...))
   
   # Subscriber - must match!
   await bus.subscribe("tasks", handler)
   ```

2. **Check subscription timing:**
   ```python
   # Subscribe BEFORE publishing
   await bus.subscribe("tasks", handler)
   await bus.publish(Message(topic="tasks", ...))
   ```

3. **Enable debug logging:**
   ```python
   import logging
   logging.getLogger("amb_core").setLevel(logging.DEBUG)
   ```

---

## IDE Extension Issues

### VS Code extension not activating

**Problem:** Shield icon doesn't appear, commands unavailable.

**Solutions:**

1. **Check extension is enabled:**
   - Open Extensions panel (Ctrl+Shift+X)
   - Search "Agent OS"
   - Ensure it's enabled

2. **Reload window:**
   - Press Ctrl+Shift+P
   - Run "Developer: Reload Window"

3. **Check Output panel:**
   - View → Output
   - Select "Agent OS" from dropdown
   - Look for error messages

### JetBrains plugin not working

**Problem:** Inspections not running.

**Solutions:**

1. **Check plugin is enabled:**
   - Settings → Plugins
   - Ensure Agent OS is checked

2. **Verify inspection settings:**
   - Settings → Editor → Inspections
   - Search "Agent OS"
   - Ensure inspections are enabled

3. **Invalidate caches:**
   - File → Invalidate Caches → Invalidate and Restart

---

## CMVK Issues

### "CMVK API error" or timeout

**Problem:** Multi-model verification fails.

**Solutions:**

1. **Check API keys are set:**
   ```bash
   echo $OPENAI_API_KEY
   echo $ANTHROPIC_API_KEY
   ```

2. **Verify API endpoint:**
   ```yaml
   cmvk:
     api_endpoint: "https://api.agent-os.dev/cmvk"
   ```

3. **Increase timeout:**
   ```python
   result = await cmvk.verify(code, timeout=60.0)
   ```

4. **Check rate limits:**
   - OpenAI, Anthropic have rate limits
   - Consider reducing concurrent requests

---

## Getting Help

If your issue isn't covered here:

1. **Search existing issues:**
   https://github.com/microsoft/agent-governance-toolkit/issues

2. **Create a new issue with:**
   - Agent OS version: `pip show agent-os`
   - Python version: `python --version`
   - OS and version
   - Minimal reproduction code
   - Full error message/stack trace

3. **Join discussions:**
   https://github.com/microsoft/agent-governance-toolkit/discussions
