#!/bin/bash
# setup.sh - Setup script for Bug Bounty Scanner

echo "🔧 Setting up Bug Bounty Scanner..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
python bb_scanner.py --create-requirements
pip install -r requirements.txt

# Create configuration
echo "⚙️ Creating configuration..."
python config/default_config.py

# Create project directories
echo "📁 Creating project directories..."
mkdir -p bb_projects logs config

# Set permissions
chmod +x bb_scanner.py

# Install additional tools (optional)
echo "🛠️ Installing additional tools..."
echo "Note: Some tools may require manual installation"

# Check for required tools
tools=("nmap" "masscan" "git" "curl" "wget")
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✅ $tool is available"
    else
        echo "❌ $tool is not available - please install manually"
    fi
done

# Download common wordlists
echo "📝 Downloading wordlists..."
mkdir -p wordlists
cd wordlists

# SecLists
if [ ! -d "SecLists" ]; then
    git clone https://github.com/danielmiessler/SecLists.git
fi

cd ..

echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit config.json with your settings"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run a scan: python bb_scanner.py --program-url https://example.com/program"
echo ""
echo "For help: python bb_scanner.py --help"