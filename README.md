# MPC v1.0 — Multi-Process Coordinator
Cyberdyne Security | Barry Kramer | April 15, 2026

Automates PAP Step 04 routing. Manages CHAIN-PIPE handoffs.
Tracks chain state across multi-window Claude sessions.

## Deploy on Render
1. Go to render.com -> New + -> Web Service
2. Connect `barrykramer-cbds/mpc-v1`
3. Render auto-detects render.yaml -> select Free -> Deploy
4. Live at: `https://mpc-v1.onrender.com/mcp/`

## Claude Desktop config
Add alongside Protocol MCP in `claude_desktop_config.json`:
```json
"mpc_cloud": {
  "command": "npx",
  "args": ["-y", "mcp-remote", "https://mpc-v1.onrender.com/mcp/"]
}
```

## Tools
| Tool | Purpose |
|---|---|
| `mpc_init` | Initialize session from SIP header |
| `mpc_route` | Route prompt — PAP Step 04 automation |
| `mpc_register_output` | Log Step 06 gate output |
| `mpc_amend` | Process SIP-AMEND events |
| `mpc_close_window` | Close window, detect dependency breaks |
| `mpc_status` | Full session state audit |

## Pipeline
```
SIP (session start) -> MPC (session management) -> PAP (per prompt) -> Submit
```

## Stack
Same deployment pattern as Protocol MCP (`protocol-mcp.onrender.com`).
v1.0 uses in-memory state. v1.1 adds DynamoDB persistence.
