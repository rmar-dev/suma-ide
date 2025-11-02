---
layout: default
title: Gate System Service
parent: Developer Guide
nav_order: 4
---

# Gate System Service API
{: .no_toc }

The Gate System Service orchestrates the 5-gate SDLC workflow, managing project lifecycle from requirements to implementation planning.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

The **Gate System Service** (`IGateSystemService`) is a workbench-level service that manages the execution of a structured 5-gate software development lifecycle workflow. It coordinates with the MCP Platform Service to execute gates and track project progress.

### Key Features

- ✅ 5-gate SDLC workflow (Pre-0, 0, 1, 1.5, 2)
- ✅ Project initialization and management
- ✅ Gate execution with dependency tracking
- ✅ Automatic blocker detection (4 types)
- ✅ Progress tracking (per-gate and overall)
- ✅ Document validation and verification
- ✅ Real-time status events
- ✅ Force execution with blocker override

---

## The 5-Gate Workflow

```
┌────────────────────────────────────────────────────────────┐
│                    SUMA 5-Gate SDLC                        │
└────────────────────────────────────────────────────────────┘

Pre-Gate 0: Prompt Engineering
├─ Input: User requirements (natural language)
├─ Output: Structured prompt templates
├─ Duration: ~15 minutes
└─ Dependencies: None

↓

Gate 0: Detailed Requirements
├─ Input: Structured prompts
├─ Output: Backend, Frontend, Database, iOS, Android specs
├─ Duration: ~30 minutes
└─ Dependencies: Pre-Gate 0

↓

Gate 1: Architecture Design
├─ Input: Gate 0 requirements
├─ Output: System architecture, component diagrams, ERD
├─ Duration: ~45 minutes
└─ Dependencies: Gate 0

↓

Gate 1.5: Cross-Validation
├─ Input: Gate 0 + Gate 1 outputs
├─ Output: Validation reports, gap analysis, recommendations
├─ Duration: ~20 minutes
└─ Dependencies: Gate 0, Gate 1

↓

Gate 2: Implementation Planning
├─ Input: Validated architecture
├─ Output: Task breakdown, sprints, dependencies, risks
├─ Duration: ~60 minutes
└─ Dependencies: Gate 1, Gate 1.5
```

---

## Architecture

```
┌─────────────────────────────────────┐
│   VSCode Extensions/Commands        │
│   (Gate Commands, UI Components)    │
└──────────────┬──────────────────────┘
               │
               │ Dependency Injection
               ▼
┌─────────────────────────────────────┐
│     Gate System Service             │
│     (GateSystemService class)       │
│                                     │
│  - Project management               │
│  - Gate execution orchestration     │
│  - Dependency validation            │
│  - Blocker detection                │
│  - Progress tracking                │
│  - Event emitters                   │
└──────────────┬──────────────────────┘
               │
               │ Uses
               ▼
┌─────────────────────────────────────┐
│     MCP Platform Service            │
│     (Executes gate tools)           │
│                                     │
│  - generate-gate0                   │
│  - generate-gate1                   │
│  - generate-gate1_5                 │
│  - generate-gate2                   │
└─────────────────────────────────────┘
```

---

## Interface Definition

### IGateSystemService

```typescript
import { IGateSystemService } from 'vs/workbench/contrib/suma/common/gates/gateSystem';

export interface IGateSystemService {
    readonly _serviceBrand: undefined;

    // Project Management
    initializeProject(name: string, rootUri: URI, config?: Partial<IGateProject>): Promise<IGateProject>;
    getProjects(): Promise<IGateProject[]>;
    getProject(projectId: string): Promise<IGateProject | undefined>;
    deleteProject(projectId: string): Promise<void>;

    // Gate Execution
    executeGate(projectId: string, gateId: GateId, options?: IGateExecutionOptions): Promise<IGateExecutionResult>;
    executeNextGate(projectId: string): Promise<IGateExecutionResult>;
    validateGate(projectId: string, gateId: GateId): Promise<IGateValidationResult[]>;
    cancelGateExecution(projectId: string, gateId: GateId): Promise<void>;

    // Status and Progress
    getGateStatus(projectId: string, gateId: GateId): Promise<IGateExecutionStatus>;
    getAllGateStatuses(projectId: string): Promise<Map<GateId, IGateExecutionStatus>>;
    getProjectSummary(projectId: string): Promise<IGateProjectSummary>;
    getGateBlockers(projectId: string, gateId: GateId): Promise<IGateBlocker[]>;

    // Events
    readonly onDidStartGateExecution: Event<{ projectId: string; gateId: GateId }>;
    readonly onDidCompleteGateExecution: Event<IGateExecutionResult>;
    readonly onDidFailGateExecution: Event<{ projectId: string; gateId: GateId; error: string }>;
    readonly onDidChangeGateStatus: Event<IGateExecutionStatus>;
    readonly onDidUpdateProgress: Event<{ projectId: string; gateId: GateId; progress: number }>;
    readonly onDidDetectBlocker: Event<IGateBlocker>;
}
```

---

## Usage Examples

### Initialize a New Project

```typescript
import { IGateSystemService } from 'vs/workbench/contrib/suma/common/gates/gateSystem';
import { URI } from 'vs/base/common/uri';

class MyComponent {
    constructor(
        @IGateSystemService private readonly gateService: IGateSystemService
    ) {}

    async initializeMyProject() {
        const project = await this.gateService.initializeProject(
            'E-Commerce Platform',
            URI.file('/path/to/project'),
            {
                requirementsUri: URI.file('/path/to/requirements.md'),
                description: 'Modern e-commerce platform with React and Go'
            }
        );

        console.log(`Project initialized: ${project.id}`);
        console.log(`Output directory: ${project.outputDirectory.fsPath}`);
    }
}
```

### Execute a Specific Gate

```typescript
async function executeArchitectureGate() {
    const gateService = accessor.get(IGateSystemService);

    // Execute Gate 1 (Architecture Design)
    const result = await gateService.executeGate(
        'my-project-id',
        GateId.Gate1
    );

    if (result.success) {
        console.log(`Gate 1 completed in ${result.duration}ms`);
        console.log(`Generated ${result.documentCount} documents`);

        // Display output files
        for (const output of result.outputs) {
            console.log(`  - ${output.fsPath}`);
        }

        // Check validation results
        const criticalIssues = result.validationResults
            ?.filter(v => !v.valid && v.severity === 'critical');

        if (criticalIssues && criticalIssues.length > 0) {
            console.warn(`Found ${criticalIssues.length} critical issues!`);
        }
    } else {
        console.error(`Gate 1 failed: ${result.error}`);
    }
}
```

### Execute Next Available Gate

```typescript
async function executeNextGate() {
    const gateService = accessor.get(IGateSystemService);

    // Get project summary first
    const summary = await gateService.getProjectSummary('my-project-id');

    if (!summary.nextGate) {
        console.log('No next gate available!');
        console.log(`Current gate: ${summary.activeGate}`);
        console.log(`Overall progress: ${summary.overallProgress}%`);
        return;
    }

    console.log(`Executing next gate: ${summary.nextGate}`);

    // Execute next gate in sequence
    const result = await gateService.executeNextGate('my-project-id');

    if (result.success) {
        console.log(`${result.gateId} completed successfully!`);
    }
}
```

### Check for Blockers Before Execution

```typescript
async function safeGateExecution() {
    const gateService = accessor.get(IGateSystemService);
    const gateId = GateId.Gate2;

    // Check blockers first
    const blockers = await gateService.getGateBlockers('my-project-id', gateId);

    if (blockers.length > 0) {
        console.log(`Found ${blockers.length} blocker(s):`);

        for (const blocker of blockers) {
            console.log(`  [${blocker.severity}] ${blocker.type}: ${blocker.description}`);

            if (blocker.resolution) {
                console.log(`    Resolution: ${blocker.resolution}`);
            }
        }

        const criticalBlockers = blockers.filter(b => b.severity === 'critical');

        if (criticalBlockers.length > 0) {
            console.error('Cannot proceed due to critical blockers!');
            return;
        }

        // Proceed with warnings only
        console.warn('Proceeding with non-critical blockers...');
    }

    // Execute gate
    const result = await gateService.executeGate('my-project-id', gateId);
}
```

### Monitor Progress with Events

```typescript
class GateProgressMonitor extends Disposable {
    constructor(
        @IGateSystemService private readonly gateService: IGateSystemService,
        @INotificationService private readonly notificationService: INotificationService
    ) {
        super();

        // Listen to gate execution start
        this._register(
            this.gateService.onDidStartGateExecution(({ projectId, gateId }) => {
                this.notificationService.info(`Started ${gateId} for project ${projectId}`);
            })
        );

        // Listen to gate completion
        this._register(
            this.gateService.onDidCompleteGateExecution(result => {
                const duration = (result.duration! / 1000).toFixed(0);
                this.notificationService.info(
                    `${result.gateId} completed in ${duration}s! Generated ${result.documentCount} documents.`
                );
            })
        );

        // Listen to gate failures
        this._register(
            this.gateService.onDidFailGateExecution(({ projectId, gateId, error }) => {
                this.notificationService.error(`${gateId} failed: ${error}`);
            })
        );

        // Listen to progress updates
        this._register(
            this.gateService.onDidUpdateProgress(({ gateId, progress }) => {
                console.log(`${gateId} progress: ${progress}%`);
            })
        );

        // Listen to blocker detection
        this._register(
            this.gateService.onDidDetectBlocker(blocker => {
                if (blocker.severity === 'critical') {
                    this.notificationService.error(`Critical blocker: ${blocker.description}`);
                } else {
                    this.notificationService.warn(`Warning: ${blocker.description}`);
                }
            })
        );
    }
}
```

### Get Project Summary

```typescript
async function displayProjectSummary() {
    const gateService = accessor.get(IGateSystemService);
    const summary = await gateService.getProjectSummary('my-project-id');

    console.log('=== Project Summary ===');
    console.log(`Project: ${summary.project.name}`);
    console.log(`Overall Progress: ${summary.overallProgress.toFixed(1)}%`);
    console.log(`Active Gate: ${summary.activeGate || 'None'}`);
    console.log(`Next Gate: ${summary.nextGate || 'None'}`);
    console.log();

    console.log('Gate Statuses:');
    for (const [gateId, status] of summary.gates) {
        const icon = status.status === GateStatus.Completed ? '✅'
            : status.status === GateStatus.InProgress ? '⏳'
            : status.status === GateStatus.Failed ? '❌'
            : status.status === GateStatus.Blocked ? '🔒'
            : '⭕';

        console.log(`  ${icon} ${gateId}: ${status.status} (${status.progress}%)`);
    }

    if (summary.blockers.length > 0) {
        console.log();
        console.log(`Blockers (${summary.blockers.length}):`);
        for (const blocker of summary.blockers) {
            console.log(`  - [${blocker.severity}] ${blocker.description}`);
        }
    }
}
```

---

## Blocker Detection

The Gate System automatically detects 4 types of blockers:

### 1. Dependency Blockers
**When**: A required dependency gate is not completed
```typescript
{
    type: 'dependency',
    gateId: GateId.Gate1,
    severity: 'critical',
    description: 'Gate 1 requires Gate 0 to be completed',
    affectedGates: [GateId.Gate1],
    resolution: 'Complete Gate 0 first'
}
```

### 2. Validation Blockers
**When**: Output documents fail validation
```typescript
{
    type: 'validation',
    gateId: GateId.Gate0,
    severity: 'critical',
    description: 'Missing required file: gate0-backend.md',
    affectedGates: [GateId.Gate0],
    resolution: 'Re-execute Gate 0 or manually create missing file'
}
```

### 3. Resource Blockers
**When**: Required files or directories are missing
```typescript
{
    type: 'resource',
    gateId: GateId.Gate0,
    severity: 'warning',
    description: 'Requirements file not found: /path/to/requirements.md',
    affectedGates: [GateId.Gate0],
    resolution: 'Provide requirements file or use default template'
}
```

### 4. Configuration Blockers
**When**: MCP service is unavailable
```typescript
{
    type: 'configuration',
    gateId: GateId.Gate0,
    severity: 'critical',
    description: 'MCP service is not running',
    affectedGates: ['*'], // Affects all gates
    resolution: 'Start MCP service via Command Palette'
}
```

---

## Gate Configuration

Each gate is configured with:

```typescript
interface IGateConfig {
    gateId: GateId;
    name: string;
    description: string;
    mcpTool: string;                    // MCP tool name
    outputDirectory: string;             // Relative output path
    expectedOutputs: string[];           // Expected file names
    dependencies: GateId[];              // Required gates
    estimatedDuration: number;           // Minutes
    priority: GatePriority;              // critical, high, medium, low
    validationRules?: IGateValidationRule[];
}
```

**Default Gate Configs**:

| Gate | MCP Tool | Output Directory | Expected Outputs | Dependencies | Duration |
|------|----------|------------------|------------------|--------------|----------|
| **Pre-Gate 0** | `generate-pre-gate0` | `Pre-Gate-0-Prompts` | 5 files | None | 15 min |
| **Gate 0** | `generate-gate0` | `Gate-0-Requirements` | 5 files | None | 30 min |
| **Gate 1** | `generate-gate1` | `Gate-1-Architecture` | 7 files | Gate 0 | 45 min |
| **Gate 1.5** | `generate-gate1_5` | `Gate-1.5-Validation` | 4 files | Gate 0, 1 | 20 min |
| **Gate 2** | `generate-gate2` | `Gate-2-Implementation` | 6 files | Gate 1, 1.5 | 60 min |

---

## Commands Available

### Command Palette (F1)

| Command | ID | Description |
|---------|----|----|
| **Initialize Project for Gates** | `suma.gates.initializeProject` | Create new gate project |
| **Execute Gate 0** | `suma.gates.executeGate0` | Run Gate 0: Detailed Requirements |
| **Execute Gate 1** | `suma.gates.executeGate1` | Run Gate 1: Architecture Design |
| **Execute Gate 1.5** | `suma.gates.executeGate1_5` | Run Gate 1.5: Cross-Validation |
| **Execute Gate 2** | `suma.gates.executeGate2` | Run Gate 2: Implementation Planning |
| **Execute Next Gate** | `suma.gates.executeNext` | Run the next available gate |
| **View Project Summary** | `suma.gates.viewSummary` | Show gate statuses and progress |
| **List Gate Projects** | `suma.gates.listProjects` | Show all initialized projects |

---

## Progress Tracking

### Per-Gate Progress
Each gate tracks progress through these stages:
1. **0%**: Pending (not started)
2. **10%**: Validating dependencies
3. **20%**: Preparing inputs
4. **30%**: Executing MCP tool
5. **60%**: MCP tool completed
6. **70%**: Validating outputs
7. **90%**: Saving results
8. **100%**: Completed

### Overall Project Progress
```
overallProgress = (completedGates / totalGates) * 100
```

Example:
- Gate 0: Completed (100%)
- Gate 1: Completed (100%)
- Gate 1.5: In Progress (60%)
- Gate 2: Pending (0%)

**Overall Progress**: `(2 + 0.6) / 4 = 65%`

---

## Error Handling

### Execution Errors

```typescript
const result = await gateService.executeGate(projectId, GateId.Gate1);

if (!result.success) {
    // Handle error
    console.error(`Gate failed: ${result.error}`);

    // Check validation results
    if (result.validationResults) {
        const failedValidations = result.validationResults.filter(v => !v.valid);
        console.log(`Failed validations: ${failedValidations.length}`);
    }
}
```

### Force Execution

Bypass blocker checks (use with caution):

```typescript
const result = await gateService.executeGate(
    projectId,
    GateId.Gate1,
    { force: true }  // Skip blocker checks
);
```

---

## Testing

### Unit Tests

```bash
npm test -- --grep "Gate System Service"
```

**Test Coverage**:
- Service Initialization (2 tests)
- Project Management (4 tests)
- Gate Execution (5 tests)
- Blocker Detection (4 tests)
- Progress Tracking (3 tests)
- Validation (3 tests)
- Events (6 tests)

---

## SOLID Principles

### Single Responsibility ✅
Only manages gate workflow orchestration and project tracking.

### Open/Closed ✅
Extensible via gate configurations, closed for modification.

### Liskov Substitution ✅
Fully implements `IGateSystemService` contract.

### Interface Segregation ✅
Clean interface focused on gate operations.

### Dependency Inversion ✅
Depends on `IMCPService`, `ILogService`, `IFileService` abstractions.

---

## API Reference

### Types

```typescript
// Gate identifiers
enum GateId {
    PreGate0 = 'pre-gate-0',
    Gate0 = 'gate0',
    Gate1 = 'gate1',
    Gate1_5 = 'gate1.5',
    Gate2 = 'gate2'
}

// Gate statuses
enum GateStatus {
    Pending = 'pending',
    InProgress = 'in_progress',
    Completed = 'completed',
    Failed = 'failed',
    Blocked = 'blocked'
}

// Project definition
interface IGateProject {
    id: string;
    name: string;
    rootUri: URI;
    requirementsUri?: URI;
    outputDirectory: URI;
    createdAt: number;
    updatedAt: number;
    description?: string;
}

// Execution result
interface IGateExecutionResult {
    success: boolean;
    gateId: GateId;
    projectId: string;
    outputs: URI[];
    duration?: number;
    documentCount?: number;
    error?: string;
    validationResults?: IGateValidationResult[];
}

// Execution status
interface IGateExecutionStatus {
    gateId: GateId;
    projectId: string;
    status: GateStatus;
    progress: number;
    startTime?: number;
    endTime?: number;
    duration?: number;
    outputs: URI[];
    error?: string;
}

// Blocker
interface IGateBlocker {
    type: 'dependency' | 'validation' | 'resource' | 'configuration';
    gateId: GateId;
    severity: 'critical' | 'warning' | 'info';
    description: string;
    affectedGates: GateId[] | '*';
    resolution?: string;
    detectedAt: number;
}

// Project summary
interface IGateProjectSummary {
    project: IGateProject;
    gates: Map<GateId, IGateExecutionStatus>;
    overallProgress: number;
    activeGate?: GateId;
    nextGate?: GateId;
    blockers: IGateBlocker[];
}
```

---

## Related Documentation

- [MCP Platform Service](/developer_guide/mcp-platform-service) - MCP tool execution
- [Architecture Overview](/developer_guide/architecture) - System design
- [Gates Workflow](/user_guide/gates-workflow) - User guide
- [Extension API](/developer_guide/extension-api) - Extend SUMA IDE

---

## Source Code

**Interface**: [src/vs/workbench/contrib/suma/common/gates/gateSystem.ts](src/vs/workbench/contrib/suma/common/gates/gateSystem.ts) (500+ lines)
**Implementation**: [src/vs/workbench/contrib/suma/node/gateSystemService.ts](src/vs/workbench/contrib/suma/node/gateSystemService.ts) (500+ lines)
**Commands**: [src/vs/workbench/contrib/suma/browser/gateCommands.ts](src/vs/workbench/contrib/suma/browser/gateCommands.ts) (350+ lines)

---

*Last updated: 2025-11-02*
