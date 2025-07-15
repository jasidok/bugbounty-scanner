# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a comprehensive bug bounty scanner framework extracted from a markdown specification. The tool is designed for authorized security testing and vulnerability assessment.

## Commands

### Setup and Installation
- `./setup.sh` - Complete setup including virtual environment and dependencies
- `make install` - Install Python dependencies only
- `make setup` - Full setup using Makefile
- `pip install -r requirements.txt` - Manual dependency installation

### Running the Scanner
- `python main.py --help` - Show all available commands
- `python main.py scan web --target <url>` - Web application scan
- `python main.py scan api --target <url>` - API security scan
- `python main.py scan contract --file <file>` - Smart contract analysis
- `python main.py project create --name <name> --url <url>` - Create new project

### Development Commands
- `make test` - Run test suite (when tests are available)
- `make lint` - Code linting and formatting
- `make docker-build` - Build Docker container
- `python -m pytest tests/` - Run tests manually

### Docker Usage
- `docker build -t bugbounty-scanner .` - Build container
- `docker run -it bugbounty-scanner` - Run scanner in container

## Architecture

### Core Components
- **core/scanner.py**: Main scanner implementation with BugBountyScanner class
- **core/automation.py**: AutomationEngine for scheduled scans and notifications
- **modules/**: Specialized scanning modules (Nuclei, mobile, smart contracts)
- **utils/**: Utility classes for payloads and evidence collection
- **reports/**: Professional report generation (PDF/Markdown)

### Key Classes
- `BugBountyScanner`: Main orchestrator class
- `WebScanner`: Web application vulnerability scanning
- `APIScanner`: REST/GraphQL API security testing
- `SmartContractScanner`: Solidity contract analysis
- `MobileAppScanner`: Mobile application security assessment
- `ProjectManager`: Project and scope management
- `ReportGenerator`: Multi-format report generation

### Data Flow
1. Target validation against scope using `ScopeValidator`
2. Scanner selection based on target type
3. Evidence collection via `EvidenceCollector`
4. Results storage in SQLite database
5. Report generation with integrated evidence

### Configuration
- Main config: `config/config.json`
- Database: SQLite files in `databases/` directory
- Reports: Generated in `reports/` directory
- Evidence: Screenshots and files in `evidence/` directory

## Security Considerations

This tool is designed for **authorized security testing only**:
- Built-in rate limiting via `RateLimiter` class
- Scope validation to prevent out-of-scope testing
- Evidence integrity with SHA256 hashing
- Professional reporting for responsible disclosure

## Development Notes

- The codebase uses dataclasses for configuration and results
- Threading is implemented for concurrent scanning
- Database operations use SQLite with proper schema
- All external tool integrations include error handling
- Rate limiting ensures ethical scanning practices