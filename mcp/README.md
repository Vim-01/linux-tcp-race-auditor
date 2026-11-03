# MCP Server: Linux TCP Race & CVE-2026-98432 Auditor

An autonomous **Model Context Protocol (MCP)** server providing security tooling to audit Linux kernels, model timing windows for sub-200µs races, and inspect TCP options safely.

## Features

- **`audit_kernel_version`**: Fast check of kernel versions against the affected/patched matrix for CVE-2026-98432.
- **`calculate_timing_window`**: Calculates race window feasibility and models the "KASAN Negative Detector" effect.
- **`inspect_tcp_options`**: Crafts and verifies IPv4 TCP Options (SSRR, Timestamp, NOP) in dry-run mode.
- **`parse_dmesg_kasan`**: Analyzes kernel dmesg logs for `kmalloc-96` slab UAF traces.
- **`explain_ebpf_observability`**: Detailed architectural reasoning on eBPF runtime blindspots in internal TCP paths.

## Zero Dependencies
Runs on pure standard-library Python (3.8+). No `pip install` required.

## Configuration for MCP Clients

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "kernel-race-auditor": {
      "command": "python3",
      "args": ["/path/to/mcp/server.py"]
    }
  }
}
```

### Custom MCP Agent / Client
Add to your agent configuration:
```json
{
  "name": "kernel-race-auditor",
  "command": "python3",
  "args": ["/path/to/mcp/server.py"]
}
```

## Testing
```bash
python3 mcp/server.py --test
```
