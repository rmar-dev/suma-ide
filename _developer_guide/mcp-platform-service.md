---
layout: default
title: MCP Platform Service
parent: Developer Guide
nav_order: 3
---

# MCP Platform Service API
{: .no_toc }

The MCP Platform Service manages the Model Context Protocol server and provides access to 27 specialized development tools.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

The **MCP Platform Service** (`IMCPService`) is a core platform service that manages a Python MCP server process and provides tool execution capabilities. It follows SOLID principles and integrates seamlessly with the VSCode dependency injection system.

### Key Features

- ✅ Python MCP server lifecycle management (start, stop, restart)
- ✅ 27 tools across 8 categories
- ✅ stdio/JSON-RPC communication
- ✅ Auto-restart on crash (configurable, max 3 attempts)
- ✅ Real-time status events
- ✅ Graceful error handling with 60-second timeouts
- ✅ Tool categorization and filtering

---

## Architecture

```
┌─────────────────────────────────────┐
│      VSCode Extensions              │
│  (Your code using IMCPService)      │
└──────────────┬──────────────────────┘
               │
               │ Dependency Injection
               ▼
┌─────────────────────────────────────┐
│     MCP Platform Service            │
│     (MCPService class)              │
│                                     │
│  - Server lifecycle management      │
│  - Tool discovery & execution       │
│  - Event emitters                   │
│  - Error handling                   │
└──────────────┬──────────────────────┘
               │
               │ stdio/JSON-RPC
               ▼
┌─────────────────────────────────────┐
│     Python MCP Server               │
│     (finance_mcp.server)            │
│                                     │
│     27 Tools available:             │
│     - Database (4 tools)            │
│     - Code Generation (2 tools)     │
│     - Compliance (2 tools)          │
│     - Documentation (3 tools)       │
│     - Requirements (4 tools)        │
│     - Gates (5 tools)               │
│     - Workflow (4 tools)            │
│     - Prompt Enhancement (3 tools)  │
└─────────────────────────────────────┘
```

---

## Interface Definition

### IMCPService

```typescript
import { IMCPService } from 'vs/platform/mcp/common/mcp';

export interface IMCPService {
    readonly _serviceBrand: undefined;

    // Tool Management
    listTools(): Promise<IMCPTool[]>;
    getToolsByCategory(category: MCPToolCategory): Promise<IMCPTool[]>;
    getTool(toolName: string): Promise<IMCPTool | undefined>;
    executeTool(toolName: string, args: any): Promise<IMCPToolResult>;

    // Server Management
    isServerRunning(): Promise<boolean>;
    startServer(config?: Partial<IMCPServerConfig>): Promise<void>;
    stopServer(): Promise<void>;
    getServerStatus(): Promise<IMCPServerStatus>;
    restartServer(): Promise<void>;

    // Events
    onDidChangeServerStatus(listener: (status: IMCPServerStatus) => void): { dispose(): void };
    onDidExecuteTool(listener: (data: { toolName: string; result: IMCPToolResult }) => void): { dispose(): void };
}
```

---

## Usage Examples

### Basic Tool Execution

```typescript
import { IMCPService } from 'vs/platform/mcp/common/mcp';

class MyComponent {
    constructor(
        @IMCPService private readonly mcpService: IMCPService
    ) {}

    async executeGate0() {
        // Execute Gate 0 tool
        const result = await this.mcpService.executeTool('generate-gate0', {
            project_name: 'MyApp',
            requirements_path: '/path/to/requirements',
            output_directory: 'Gate-0-Requirements'
        });

        if (result.isError) {
            console.error('Gate 0 failed:', result.errorMessage);
            return;
        }

        // Process results
        for (const content of result.content) {
            if (content.type === 'text') {
                console.log('Generated:', content.text);
            }
        }
    }
}
```

### Listing and Filtering Tools

```typescript
async function showToolsByCategory() {
    const mcpService = accessor.get(IMCPService);

    // List all tools
    const allTools = await mcpService.listTools();
    console.log(`Total tools: ${allTools.length}`);

    // Filter by category
    const databaseTools = await mcpService.getToolsByCategory(MCPToolCategory.Database);
    console.log(`Database tools: ${databaseTools.length}`);

    // Get specific tool
    const tool = await mcpService.getTool('query-dev-database');
    if (tool) {
        console.log(`Tool: ${tool.name}`);
        console.log(`Description: ${tool.description}`);
        console.log(`Category: ${tool.category}`);
    }
}
```

### Server Management

```typescript
async function manageServer() {
    const mcpService = accessor.get(IMCPService);

    // Check if running
    const isRunning = await mcpService.isServerRunning();
    console.log(`Server running: ${isRunning}`);

    // Get detailed status
    const status = await mcpService.getServerStatus();
    console.log(`Tools: ${status.tools}`);
    console.log(`Uptime: ${status.uptime}ms`);
    console.log(`PID: ${status.pid}`);

    // Start with custom config
    if (!isRunning) {
        await mcpService.startServer({
            mode: 'stdio',
            debug: true,
            autoRestart: true,
            maxRestarts: 3
        });
    }

    // Restart server
    await mcpService.restartServer();
}
```

### Event Handling

```typescript
class MyStatusComponent extends Disposable {
    constructor(
        @IMCPService private readonly mcpService: IMCPService
    ) {
        super();

        // Listen to status changes
        this._register(
            this.mcpService.onDidChangeServerStatus(status => {
                this.updateUI(status);
            })
        );

        // Listen to tool executions
        this._register(
            this.mcpService.onDidExecuteTool(({ toolName, result }) => {
                console.log(`Tool executed: ${toolName}`);
                console.log(`Success: ${!result.isError}`);
            })
        );
    }

    private updateUI(status: IMCPServerStatus) {
        // Update your UI based on status
        if (status.running) {
            this.showStatus(`MCP: ${status.tools} tools available`);
        } else {
            this.showStatus('MCP: Offline');
        }
    }
}
```

---

## Tool Categories

| Category | Count | Examples |
|----------|-------|----------|
| **Database** | 4 | `list-database-tables`, `query-dev-database`, `get-table-schema` |
| **Code Generation** | 2 | `generate-go-endpoint`, `generate-react-component` |
| **Compliance** | 2 | `check-gdpr-compliance`, `audit-security` |
| **Documentation** | 3 | `generate-docs`, `update-readme` |
| **Requirements** | 4 | `parse-requirements`, `enrich-requirements` |
| **Gates** | 5 | `generate-gate0`, `generate-gate1`, `validate-gate2-5` |
| **Workflow** | 4 | `process-gates`, `workflow-orchestrator` |
| **Prompt Enhancement** | 3 | `enhance-prompt`, `enrich-context` |

---

## Configuration

### Server Configuration

```typescript
interface IMCPServerConfig {
    port?: number;              // HTTP port (if using HTTP mode)
    mode: 'stdio' | 'http';     // Communication mode
    pythonPath?: string;        // Custom Python executable
    serverPath: string;         // Path to MCP server module
    debug?: boolean;            // Enable debug logging
    autoRestart?: boolean;      // Auto-restart on crash
    maxRestarts?: number;       // Max restart attempts
}
```

**Default Configuration**:
```typescript
{
    mode: 'stdio',
    serverPath: path.join(__dirname, '../../../suma/mcp-server'),
    debug: false,
    autoRestart: true,
    maxRestarts: 3
}
```

---

## Error Handling

### Graceful Degradation

The service never throws exceptions from `executeTool()`. Instead, it returns error results:

```typescript
const result = await mcpService.executeTool('my-tool', args);

if (result.isError) {
    // Handle error gracefully
    console.error('Tool failed:', result.errorMessage);
    // result.content may contain error details
} else {
    // Process successful result
    processResult(result.content);
}
```

### Auto-Restart on Crash

If the MCP server process crashes:
1. Service detects crash via process exit event
2. If `autoRestart` is enabled and `restartCount < maxRestarts`:
   - Waits 5 seconds
   - Attempts to restart server
   - Increments restart counter
3. If max restarts reached:
   - Logs error
   - Notifies user
   - Status bar shows "❌ MCP: Offline"

---

## Performance Considerations

### Lazy Instantiation

Service is registered with `InstantiationType.Delayed`:
```typescript
registerSingleton(IMCPService, MCPService, InstantiationType.Delayed);
```
- Created only when first requested
- Reduces IDE startup time

### Request Timeout

All MCP requests timeout after 60 seconds:
```typescript
setTimeout(() => {
    if (this.pendingRequests.has(id)) {
        reject(new Error('Request timeout'));
    }
}, 60000);
```

### Status Update Throttling

Status bar updates every 5 seconds (not on every change) to reduce CPU usage.

---

## Testing

### Unit Tests

```bash
npm test -- --grep "MCP Service"
```

**Test Suites**:
- Service Initialization (4 tests)
- Tool Management (3 tests)
- Server Lifecycle (4 tests)
- Tool Execution (2 tests)
- Events (3 tests)
- Configuration (1 test)
- Error Handling (2 tests)
- Cleanup (2 tests)

### Integration Tests

Integration tests require actual Python MCP server:

```typescript
// Enable by changing test.skip to test
test('should start server successfully', async () => {
    const mcpService = new MCPService(logService);
    await mcpService.startServer();

    const isRunning = await mcpService.isServerRunning();
    assert.strictEqual(isRunning, true);

    await mcpService.stopServer();
});
```

---

## SOLID Principles

### Single Responsibility ✅
Only manages MCP server lifecycle and tool execution.

### Open/Closed ✅
Extensible via configuration, closed for modification.

### Liskov Substitution ✅
Fully implements `IMCPService` contract.

### Interface Segregation ✅
Clean, focused interface with clear methods.

### Dependency Inversion ✅
Depends on `ILogService` abstraction, not concrete implementation.

---

## API Reference

### Types

```typescript
// Tool definition
interface IMCPTool {
    name: string;
    description: string;
    category: MCPToolCategory;
    inputSchema: any;
}

// Tool execution result
interface IMCPToolResult {
    content: IMCPToolContent[];
    isError?: boolean;
    errorMessage?: string;
}

// Tool content
interface IMCPToolContent {
    type: 'text' | 'resource' | 'image';
    text?: string;
    resource?: string;
    imageData?: string;
    mimeType?: string;
}

// Server status
interface IMCPServerStatus {
    running: boolean;
    tools: number;
    uptime: number;
    lastError?: string;
    version?: string;
    pid?: number;
}
```

---

## Related Documentation

- [Gate System Service](/developer_guide/gate-system-service) - Gate workflow orchestration
- [Architecture Overview](/developer_guide/architecture) - System design
- [Extension API](/developer_guide/extension-api) - Extend SUMA IDE
- [MCP Protocol](/developer_guide/mcp-protocol) - Protocol details

---

## Source Code

**Interface**: `src/vs/platform/mcp/common/mcp.ts` (210 lines)
**Implementation**: `src/vs/platform/mcp/node/mcpService.ts` (400+ lines)
**Tests**: `src/vs/platform/mcp/test/mcpService.test.ts` (300+ lines)

---

*Last updated: 2025-11-02*
