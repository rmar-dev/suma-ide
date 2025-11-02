# SUMA IDE Documentation

**Live Site**: [https://ricmar-dev.github.io/suma-ide/](https://ricmar-dev.github.io/suma-ide/)

This repository contains the documentation for SUMA IDE, built with Jekyll and GitHub Pages.

## Features

✅ Full Markdown support
✅ Mermaid diagrams rendering
✅ Search functionality
✅ Dark/Light mode
✅ Mobile responsive
✅ Auto-deployment via GitHub Actions

## Local Development

### Prerequisites

- Ruby 3.2+
- Bundler

### Setup

```bash
# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Open browser to http://localhost:4000/suma-ide/
```

## Structure

```
.
├── _config.yml              # Jekyll configuration
├── index.md                 # Home page
├── _user_guide/            # User documentation
├── _developer_guide/       # Developer documentation
├── _requirements/          # Requirements docs
├── _api/                   # API reference
├── _includes/              # Custom includes (Mermaid support)
└── assets/                 # Static assets
```

## Deployment

This site auto-deploys to GitHub Pages on every push to `main` branch.

## License

MIT License - Copyright © 2025 SUMA IDE Team
