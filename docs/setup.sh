#!/bin/bash

# Network Traffic Analysis Toolkit - Setup Script
# ================================================
# This script installs and configures all necessary tools for network traffic analysis

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$TOOLKIT_DIR/setup.log"
PYTHON_MIN_VERSION="3.8"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
    log "INFO: $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING: $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "ERROR: $1"
}

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Check if running as root when needed
check_root() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            OS="debian"
        elif command -v yum >/dev/null 2>&1; then
            OS="redhat"
        elif command -v pacman >/dev/null 2>&1; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        OS="unknown"
    fi
    
    print_status "Detected OS: $OS"
}

# Check Python version
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        
        # Compare versions
        if [ "$(printf '%s\n' "$PYTHON_MIN_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$PYTHON_MIN_VERSION" ]; then
            print_status "Python $PYTHON_VERSION detected (meets minimum requirement of $PYTHON_MIN_VERSION)"
            PYTHON_CMD="python3"
        else
            print_error "Python $PYTHON_VERSION detected, but $PYTHON_MIN_VERSION or higher is required"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python $PYTHON_MIN_VERSION or higher"
        exit 1
    fi
}

# Install system packages
install_system_packages() {
    print_header "Installing System Packages"
    
    case $OS in
        "debian")
            print_status "Updating package lists..."
            sudo apt-get update
            
            print_status "Installing required packages..."
            sudo apt-get install -y \
                wireshark \
                tshark \
                tcpdump \
                nmap \
                dsniff \
                python3-pip \
                python3-venv \
                python3-dev \
                libpcap-dev \
                build-essential \
                git \
                curl \
                wget
            
            # Add user to wireshark group
            print_status "Configuring Wireshark permissions..."
            if ! groups $USER | grep -q wireshark; then
                sudo usermod -a -G wireshark $USER
                print_warning "User added to wireshark group. Please log out and back in for changes to take effect."
            fi
            ;;
            
        "redhat")
            print_status "Installing required packages..."
            sudo yum install -y \
                wireshark \
                tcpdump \
                nmap \
                python3-pip \
                python3-devel \
                libpcap-devel \
                gcc \
                git \
                curl \
                wget
            ;;
            
        "arch")
            print_status "Installing required packages..."
            sudo pacman -S --noconfirm \
                wireshark-qt \
                tcpdump \
                nmap \
                python-pip \
                libpcap \
                base-devel \
                git \
                curl \
                wget
            ;;
            
        "macos")
            print_status "Installing packages via Homebrew..."
            if ! command -v brew >/dev/null 2>&1; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            brew install wireshark tcpdump nmap python3 git
            ;;
            
        *)
            print_warning "Unsupported OS: $OS. Please install packages manually:"
            echo "  - Wireshark"
            echo "  - TCPDump"
            echo "  - Python 3.8+"
            echo "  - Git"
            ;;
    esac
}

# Create Python virtual environment
setup_python_environment() {
    print_header "Setting up Python Environment"
    
    VENV_DIR="$TOOLKIT_DIR/venv"
    
    if [ -d "$VENV_DIR" ]; then
        print_status "Virtual environment already exists"
    else
        print_status "Creating Python virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
    fi
    
    print_status "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
    
    print_status "Upgrading pip..."
    pip install --upgrade pip
    
    print_status "Installing Python requirements..."
    if [ -f "$TOOLKIT_DIR/requirements.txt" ]; then
        pip install -r "$TOOLKIT_DIR/requirements.txt"
    else
        # Install essential packages
        pip install \
            scapy \
            pyshark \
            pandas \
            numpy \
            matplotlib \
            seaborn \
            netaddr \
            python-nmap \
            requests \
            jinja2 \
            pyyaml \
            click \
            colorama \
            tqdm
    fi
}

# Install specialized security tools
install_security_tools() {
    print_header "Installing Security Tools"
    
    TOOLS_DIR="$TOOLKIT_DIR/external-tools"
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR"
    
    # Install PCredz
    print_status "Installing PCredz..."
    if [ ! -d "PCredz" ]; then
        git clone https://github.com/lgandx/PCredz.git
        cd PCredz
        pip install Cython python-libpcap
        cd ..
    else
        print_status "PCredz already installed"
    fi
    
    # Install CredSlayer
    print_status "Installing CredSlayer..."
    pip install credslayer
    
    # Install NetworkMiner (if on Linux with Mono)
    if [[ "$OS" == "debian" ]]; then
        print_status "Installing NetworkMiner dependencies..."
        sudo apt-get install -y mono-complete
        
        if [ ! -f "NetworkMiner.zip" ]; then
            print_status "Downloading NetworkMiner..."
            wget https://www.netresec.com/?download=NetworkMinerFree -O NetworkMiner.zip
            unzip NetworkMiner.zip
        else
            print_status "NetworkMiner already downloaded"
        fi
    fi
    
    cd "$TOOLKIT_DIR"
}

# Configure tools
configure_tools() {
    print_header "Configuring Tools"
    
    # Create configuration directory
    CONFIG_DIR="$TOOLKIT_DIR/config"
    mkdir -p "$CONFIG_DIR"
    
    # Create Wireshark preferences (if not exists)
    if [ ! -f "$CONFIG_DIR/wireshark-preferences.cfg" ]; then
        print_status "Creating Wireshark configuration..."
        cat > "$CONFIG_DIR/wireshark-preferences.cfg" << EOF
# Wireshark Preferences for Network Security Analysis

# GUI preferences
gui.qt.language: "en"
gui.recent_df_entries_max: 100
gui.recent_files_count_max: 100

# Protocol preferences
http.desegment_headers: TRUE
http.desegment_body: TRUE
http.dechunk_body: TRUE
tcp.desegment_tcp_streams: TRUE
tcp.analyze_sequence_numbers: TRUE
tcp.track_bytes_in_flight: TRUE

# Display preferences  
gui.column.format: 
  "No.", "%m",
  "Time", "%t",
  "Source", "%s", 
  "Destination", "%d",
  "Protocol", "%p",
  "Length", "%L",
  "Info", "%i"

# Security analysis preferences
ssl.desegment_ssl_records: TRUE
ssl.desegment_ssl_application_data: TRUE
ssh.desegment_ssh_buffers: TRUE

# Name resolution
nameres.network_name: TRUE
nameres.transport_name: TRUE
nameres.concurrent_dns: 50
nameres.dns_pkt_addr_resolution: TRUE
EOF
    fi
    
    # Create analysis settings
    if [ ! -f "$CONFIG_DIR/analysis-settings.json" ]; then
        print_status "Creating analysis configuration..."
        cat > "$CONFIG_DIR/analysis-settings.json" << EOF
{
    "capture_settings": {
        "default_interface": "eth0",
        "max_packet_count": 100000,
        "capture_filter": "not port 22",
        "buffer_size": "100MB"
    },
    "analysis_settings": {
        "credential_extraction": true,
        "suspicious_activity_detection": true,
        "generate_statistics": true,
        "deep_packet_inspection": true,
        "protocol_analysis": true
    },
    "output_settings": {
        "report_format": "markdown",
        "include_screenshots": false,
        "evidence_retention_days": 90,
        "output_directory": "./results",
        "log_level": "INFO"
    },
    "security_patterns": {
        "enable_credential_patterns": true,
        "enable_malware_detection": true,
        "enable_data_exfiltration_detection": true,
        "custom_patterns_file": "config/custom-patterns.txt"
    }
}
EOF
    fi
}

# Create directory structure
create_directories() {
    print_header "Creating Directory Structure"
    
    DIRS=(
        "results"
        "logs" 
        "temp"
        "exports"
        "pcap-samples"
        "external-tools"
    )
    
    for dir in "${DIRS[@]}"; do
        mkdir -p "$TOOLKIT_DIR/$dir"
        print_status "Created directory: $dir"
    done
    
    # Create .gitkeep files for empty directories
    touch "$TOOLKIT_DIR/results/.gitkeep"
    touch "$TOOLKIT_DIR/logs/.gitkeep"
    touch "$TOOLKIT_DIR/temp/.gitkeep"
    touch "$TOOLKIT_DIR/exports/.gitkeep"
}

# Set up aliases and environment
setup_environment() {
    print_header "Setting up Environment"
    
    # Create environment setup script
    ENV_SCRIPT="$TOOLKIT_DIR/activate.sh"
    cat > "$ENV_SCRIPT" << EOF
#!/bin/bash
# Network Traffic Analysis Toolkit Environment

# Activate Python virtual environment
source "$TOOLKIT_DIR/venv/bin/activate"

# Set environment variables
export TOOLKIT_HOME="$TOOLKIT_DIR"
export PCAP_DIR="$TOOLKIT_DIR/pcap-samples"
export RESULTS_DIR="$TOOLKIT_DIR/results"
export TOOLS_DIR="$TOOLKIT_DIR/external-tools"
export PATH="$TOOLKIT_DIR/scripts:$TOOLKIT_DIR/tools/automated-tools:\$PATH"

# Helpful aliases
alias pcap-analyze="python3 $TOOLKIT_DIR/tools/automated-tools/credential-extractor.py"
alias traffic-scan="python3 $TOOLKIT_DIR/tools/automated-tools/traffic-analyzer.py"
alias generate-report="python3 $TOOLKIT_DIR/tools/automated-tools/report-generator.py"
alias wireshark-filters="cat $TOOLKIT_DIR/tools/wireshark-filters/security-filters.txt"
alias tcpdump-help="bash $TOOLKIT_DIR/tools/tcpdump-commands/basic-capture.sh"

# Tool shortcuts
alias pcredz="python3 $TOOLS_DIR/PCredz/Pcredz.py"
alias credslayer="credslayer"

echo "🔍 Network Traffic Analysis Toolkit Environment Activated"
echo "📍 Toolkit Home: \$TOOLKIT_HOME"
echo "📊 PCAP Directory: \$PCAP_DIR" 
echo "📋 Results Directory: \$RESULTS_DIR"
echo ""
echo "Available commands:"
echo "  pcap-analyze <file.pcap>  - Analyze PCAP for credentials"
echo "  traffic-scan <file.pcap>  - Full traffic analysis"
echo "  generate-report <dir>     - Generate security report"
echo "  wireshark-filters         - Show Wireshark filters"
echo "  tcpdump-help             - Show TCPDump commands"
EOF

    chmod +x "$ENV_SCRIPT"
    print_status "Environment setup script created: $ENV_SCRIPT"
    
    # Add to shell profile if desired
    read -p "Add toolkit to shell profile (~/.bashrc)? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! grep -q "# Network Traffic Analysis Toolkit" ~/.bashrc; then
            cat >> ~/.bashrc << EOF

# Network Traffic Analysis Toolkit
alias activate-toolkit="source $ENV_SCRIPT"
EOF
            print_status "Added alias 'activate-toolkit' to ~/.bashrc"
            print_status "Run 'source ~/.bashrc' or restart terminal to use alias"
        else
            print_status "Toolkit already added to ~/.bashrc"
        fi
    fi
}

# Test installation
test_installation() {
    print_header "Testing Installation"
    
    # Test commands
    COMMANDS=(
        "wireshark --version"
        "tshark --version"
        "tcpdump --version"
        "python3 --version"
        "nmap --version"
    )
    
    for cmd in "${COMMANDS[@]}"; do
        if eval "$cmd" >/dev/null 2>&1; then
            print_status "✅ $cmd"
        else
            print_warning "❌ $cmd (failed)"
        fi
    done
    
    # Test Python packages
    print_status "Testing Python packages..."
    source "$TOOLKIT_DIR/venv/bin/activate"
    
    PYTHON_PACKAGES=(
        "scapy"
        "pyshark" 
        "pandas"
        "numpy"
        "matplotlib"
    )
    
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if python3 -c "import $pkg" >/dev/null 2>&1; then
            print_status "✅ Python package: $pkg"
        else
            print_warning "❌ Python package: $pkg (failed)"
        fi
    done
    
    # Test toolkit scripts
    if [ -f "$TOOLKIT_DIR/tools/automated-tools/credential-extractor.py" ]; then
        if python3 "$TOOLKIT_DIR/tools/automated-tools/credential-extractor.py" --help >/dev/null 2>&1; then
            print_status "✅ Credential extractor script"
        else
            print_warning "❌ Credential extractor script (failed)"
        fi
    fi
}

# Create sample data
create_sample_data() {
    print_header "Creating Sample Data"
    
    SAMPLE_DIR="$TOOLKIT_DIR/sample-data"
    mkdir -p "$SAMPLE_DIR/pcap-files"
    
    # Create sample analysis results file
    cat > "$SAMPLE_DIR/analysis-results/sample_results.json" << 'EOF'
{
    "metadata": {
        "analysis_timestamp": "2024-09-18T10:30:00",
        "analyzer_version": "2.1.0",
        "total_credentials": 3,
        "total_suspicious_patterns": 5
    },
    "credentials": [
        {
            "protocol": "HTTP POST",
            "type": "password",
            "field_name": "password",
            "value": "admin123",
            "source_ip": "192.168.1.45",
            "destination_ip": "203.0.113.10",
            "url": "login.php",
            "timestamp": "2024-09-18T10:15:23"
        }
    ],
    "summary": {
        "risk_level": "HIGH",
        "recommendations": [
            "Implement HTTPS for all web applications",
            "Use strong password policies",
            "Enable multi-factor authentication"
        ]
    }
}
EOF

    print_status "Sample data created in $SAMPLE_DIR"
}

# Main installation function
main() {
    print_header "Network Traffic Analysis Toolkit Setup"
    print_status "Starting installation process..."
    
    # Initialize log file
    echo "Setup started at $(date)" > "$LOG_FILE"
    
    # Run setup steps
    detect_os
    check_python
    
    # Check for required permissions
    if ! check_root && [[ "$OS" != "macos" ]]; then
        print_warning "Some installation steps require sudo privileges"
        print_status "You may be prompted for your password during installation"
    fi
    
    install_system_packages
    setup_python_environment
    install_security_tools
    configure_tools
    create_directories
    create_sample_data
    setup_environment
    test_installation
    
    print_header "Installation Complete!"
    print_status "🎉 Network Traffic Analysis Toolkit has been successfully installed!"
    echo ""
    print_status "Next steps:"
    echo "1. If you added toolkit to shell profile, run: source ~/.bashrc"
    echo "2. To activate the toolkit environment: source $TOOLKIT_DIR/activate.sh"
    echo "3. Or use the alias: activate-toolkit (if added to profile)"
    echo "4. Read the documentation: $TOOLKIT_DIR/docs/user-manual.md"
    echo "5. Try analyzing a sample PCAP file"
    echo ""
    print_status "For support, visit: https://github.com/your-org/network-traffic-analysis-toolkit"
    
    # Show final status
    echo ""
    print_header "Installation Summary"
    echo "📁 Installation Directory: $TOOLKIT_DIR"
    echo "🐍 Python Environment: $TOOLKIT_DIR/venv"
    echo "⚙️  Configuration: $TOOLKIT_DIR/config"
    echo "📊 Sample Data: $TOOLKIT_DIR/sample-data"
    echo "📝 Log File: $LOG_FILE"
    echo ""
    print_status "Installation completed successfully! 🚀"
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 1' INT TERM

# Run main installation
main "$@"