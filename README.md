# Bug Bounty Scanner Framework

A comprehensive security testing toolkit designed for ethical bug bounty research and vulnerability assessment.

## ⚠️ Important Notice

This tool is designed exclusively for **authorized security testing** on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

## Features

- **Web Application Scanning**: Comprehensive vulnerability detection
- **API Security Testing**: REST/GraphQL endpoint analysis  
- **Smart Contract Analysis**: Solidity security testing
- **Mobile App Security**: APK/IPA vulnerability assessment
- **Automated Reporting**: Professional PDF/Markdown reports
- **Nuclei Integration**: Template-based vulnerability scanning
- **Continuous Monitoring**: Scheduled security assessments

## Installation

### Quick Setup
```bash
chmod +x setup.sh
./setup.sh
```

### Manual Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p {reports,evidence,databases}
```

### Docker Setup
```bash
make docker-build
docker run -it bugbounty-scanner
```

## Usage

### Basic Scanning
```bash
# Web application scan
python main.py scan web --target https://example.com

# API scan
python main.py scan api --target https://api.example.com

# Smart contract analysis
python main.py scan contract --file contract.sol

# Mobile app scan
python main.py scan mobile --apk app.apk
```

### Project Management
```bash
# Create new project
python main.py project create --name "Example Corp" --url https://example.com

# List projects
python main.py project list

# Generate report
python main.py report --project "Example Corp" --format pdf
```

## Configuration

Edit `config/config.json` to customize:
- Scanning parameters
- Rate limiting settings
- Notification preferences
- Tool integrations

## Project Structure

```
bugbounty-scanner/
├── core/                 # Core scanner functionality
│   ├── scanner.py       # Main scanner classes
│   └── automation.py    # Automation engine
├── modules/             # Specialized scanners
│   ├── nuclei_integration.py
│   ├── smart_contract_tools.py
│   └── mobile_tools.py
├── utils/               # Utilities
│   ├── payload_generator.py
│   └── evidence_collector.py
├── reports/             # Report generation
│   └── report_generator.py
├── config/              # Configuration files
├── scripts/             # Helper scripts
└── tests/               # Test suite
```

## Legal & Ethical Guidelines

- Only test systems you own or have written authorization to test
- Respect scope limitations and program guidelines
- Follow responsible disclosure practices
- Maintain evidence integrity and confidentiality
- Comply with local laws and regulations

## Contributing

This is a security research tool. Contributions should focus on:
- Defensive security capabilities
- Ethical testing methodologies
- Report generation improvements
- Integration with legitimate security tools

## License

This tool is provided for educational and authorized security testing purposes only.