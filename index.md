---
layout: default
title: Home
nav_order: 1
description: "SUMA IDE - A VSCode fork with native MCP integration and full SDLC gating system"
permalink: /
---

# SUMA IDE Documentation

**SUMA IDE** - A VSCode fork with native MCP integration and full SDLC gating system
{: .fs-6 .fw-300 }

[Get Started](/user_guide/getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/rmar-dev/suma-ide){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Welcome

SUMA IDE is an intelligent development environment that brings automated software development lifecycle (SDLC) management directly into your IDE. With native Model Context Protocol (MCP) integration, AI-powered gates, and comprehensive requirements management, SUMA IDE transforms how you build software.

---

## Quick Navigation

### 👤 For Users
{: .text-blue-200 }

- [Getting Started](/user_guide/getting-started) - Installation and setup
- [Gate System Overview](/user_guide/gate-system-overview) - Learn the 5-gate workflow
- [Requirements Manager](/user_guide/requirements-manager) - Write and manage requirements
- [MCP Tools Reference](/user_guide/mcp-tools-reference) - All 27 built-in tools
- [Tutorials](/user_guide/tutorials) - Step-by-step guides

### 🔧 For Developers
{: .text-green-200 }

- [Architecture Overview](/developer_guide/architecture) - System design and components
- [Contributing Guide](/developer_guide/contributing) - How to contribute
- [Building from Source](/developer_guide/building-from-source) - Build instructions
- [Extension API](/developer_guide/extension-api) - Extend SUMA IDE
- [MCP Protocol](/developer_guide/mcp-protocol) - Implementation details

### 📋 Requirements & Planning
{: .text-purple-200 }

- [Requirements Overview](/requirements/overview) - Documentation standards
- [Gate Documentation](/requirements/gates) - Gate-specific guides
- [Templates](/requirements/templates) - Starter templates

### ⭐ Features & Examples
{: .text-orange-200 }

- [Live Examples](/features/) - Real gate system outputs
- [User Authentication](/features/user-authentication) - Complete auth feature with all gates

### 🔌 API Reference
{: .text-yellow-200 }

- [MCP Tools API](/api/mcp-tools) - MCP tools reference
- [Gate System API](/api/gate-system) - Gate APIs
- [Claude Integration API](/api/claude-integration) - AI integration

---

## What Makes SUMA IDE Different?

| Feature | Standard IDE | SUMA IDE |
|:--------|:-------------|:---------|
| **MCP Integration** | Extension only | ✅ Native, built-in |
| **Gates System** | Not available | ✅ Native 5-gate workflow |
| **Requirements Manager** | Extensions | ✅ Built-in with syntax highlighting |
| **Claude Integration** | Extensions | ✅ Native CLI bridge + skills |
| **AI Assistant** | Paid add-ons | ✅ Built-in with MCP tools (free) |
| **SDLC Workflow** | Manual | ✅ Automated gates |
| **Prompt Enrichment** | Not available | ✅ Native codebase analysis |
| **Multi-platform Gen** | Manual | ✅ Automated (Go/React/Swift/Kotlin) |
| **Compliance Checks** | Extensions | ✅ Built-in GDPR/PCI-DSS/SOC2 |

---

## Key Features

### 🚀 5-Gate SDLC System

Automated workflow from requirements to production-ready code:

- **Pre-Gate 0**: Intelligent prompt enrichment
- **Gate 0**: Requirements parsing and validation
- **Gate 1**: Architecture generation
- **Gate 1.5**: Cross-validation and compliance
- **Gate 2**: Detailed design and implementation planning
- **Gate 2.5**: Final validation and ticket generation
- **Gate 3**: Code generation and testing

### 🔧 27 Built-in MCP Tools

Categories:
- Database tools (schema generation, migrations)
- Code generation (multi-platform support)
- Compliance validation (GDPR, PCI-DSS, SOC2)
- Documentation generation
- Requirements management
- Gate orchestration
- Workflow automation

### 🤖 Native Claude Integration

- CLI bridge for skill execution
- Automatic codebase analysis
- Context-aware prompt enrichment
- Natural language gate execution

### 📋 Requirements Manager

- Syntax highlighting for requirements files
- Tree view explorer
- Real-time validation
- Automatic enrichment

---

## Getting Started in 5 Minutes

1. **Install SUMA IDE**
   ```bash
   # Download from releases
   # Run installer for your platform
   ```

2. **Create Your First Project**
   - File > New SUMA Project
   - Choose template (Web App, Mobile App, etc.)

3. **Write Requirements**
   ```markdown
   # requirements.md

   ## REQ-AUTH-001: User Login
   Priority: CRITICAL

   The system SHALL provide secure user authentication...
   ```

4. **Execute Gates**
   - Open Gates Explorer (Activity Bar)
   - Right-click Project > Execute Gate 0
   - Review generated artifacts

5. **Review Results**
   - View architecture diagrams
   - Check design documents
   - Generate implementation tickets

[Read the full Getting Started guide →](/user_guide/getting-started)

---

## Community & Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/rmar-dev/suma-ide/issues)
- **Discussions**: [Join the community](https://github.com/rmar-dev/suma-ide/discussions)
- **Discord**: [Chat with other users](#)
- **Email**: support@suma-ide.dev

---

## Version Information

- **Current Version**: 1.0.0-beta
- **Based on**: VSCode 1.94.0
- **Last Updated**: 2025-11-02

---

## Contributing

SUMA IDE is open source! We welcome contributions from the community.

See the [Contributing Guide](/developer_guide/contributing) to get started.

---

## License

SUMA IDE is licensed under the MIT License. See [LICENSE](https://github.com/rmar-dev/suma-ide/blob/main/LICENSE) for details.
