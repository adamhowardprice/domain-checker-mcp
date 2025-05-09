# domain-checker-mcp

Give LLM an ability to check if domain is available or already registered. Runs requests concurrently.

## Tools

- check_domain
- check_keywords
- check_keywords_batch

## Installation

### Install dependencies

With `uv`:

```
uv venv
source .venv/bin/activate
uv sync
```

or:

```
uv pip install mcp aiodns httpx pytest pytest-mock pytest-asyncio
```

or if you don't have `uv`:

```
pip install mcp aiodns httpx pytest pytest-mock pytest-asyncio
```

### Testing

Run `pytest`.

### MCP config

edit your claude_desktop_config.json file (linux ~/.config/Claude/claude_desktop_config.json)

```
{
  "mcpServers": {
    "domain-checker": {
      "command": "python3",
      "args": [
        "/path/to/the/domain-checker-mcp/simple-domain-checker-server.py"
      ]
    }
  }
}
```
