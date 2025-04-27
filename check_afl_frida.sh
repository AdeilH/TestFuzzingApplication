#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AFL++ Frida Mode Checker ===${NC}\n"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for AFL++
echo -e "${YELLOW}[*] Checking for AFL++...${NC}"
if command_exists afl-fuzz; then
    AFL_PATH=$(which afl-fuzz)
    echo -e "${GREEN}[+] Found AFL++ at: $AFL_PATH${NC}"
    
    # Get AFL++ version
    AFL_VERSION=$(afl-fuzz -V 2>&1 | head -n1)
    echo -e "${GREEN}[+] AFL++ version: $AFL_VERSION${NC}"
else
    echo -e "${RED}[!] AFL++ not found!${NC}"
    exit 1
fi

# Check for Frida mode components
echo -e "\n${YELLOW}[*] Checking for Frida mode...${NC}"
FRIDA_MODE_PATH="/usr/lib/afl/frida-mode"

if [ -d "$FRIDA_MODE_PATH" ]; then
    echo -e "${GREEN}[+] Found Frida mode at: $FRIDA_MODE_PATH${NC}"
    
    # List Frida mode components
    echo -e "${YELLOW}[*] Frida mode components:${NC}"
    ls -l $FRIDA_MODE_PATH
else
    echo -e "${RED}[!] Frida mode not found at $FRIDA_MODE_PATH${NC}"
fi

# Check for afl-frida
echo -e "\n${YELLOW}[*] Checking for afl-frida...${NC}"
if command_exists afl-frida; then
    FRIDA_PATH=$(which afl-frida)
    echo -e "${GREEN}[+] Found afl-frida at: $FRIDA_PATH${NC}"
else
    echo -e "${RED}[!] afl-frida not found${NC}"
fi

# Check Frida Python package
echo -e "\n${YELLOW}[*] Checking Frida Python package...${NC}"
if python3 -c "import frida" 2>/dev/null; then
    FRIDA_VERSION=$(python3 -c "import frida; print(frida.__version__)")
    echo -e "${GREEN}[+] Frida Python package installed (version: $FRIDA_VERSION)${NC}"
else
    echo -e "${RED}[!] Frida Python package not found${NC}"
fi

# Function to run a quick Frida mode test
test_frida_mode() {
    echo -e "\n${YELLOW}[*] Running Frida mode test...${NC}"
    
    # Create test directory
    TEST_DIR="/tmp/afl_frida_test"
    mkdir -p "$TEST_DIR/input"
    cd "$TEST_DIR"
    
    # Create test program
    cat > test.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    char buf[100];
    if(fgets(buf, sizeof(buf), stdin)) {
        if(strlen(buf) > 10) {
            printf("Input too long!\n");
        } else {
            printf("Input: %s", buf);
        }
    }
    return 0;
}
EOF
    
    # Compile test program
    gcc -o test test.c
    
    # Create initial input
    echo "test" > input/test.txt
    
    # Run AFL++ with Frida mode
    echo -e "${YELLOW}[*] Starting AFL++ in Frida mode (will run for 5 seconds)...${NC}"
    timeout 5 afl-fuzz -O -i input -o output -F ./test >/dev/null 2>&1
    
    # Check results
    if [ -d "output" ]; then
        echo -e "${GREEN}[+] Test completed successfully!${NC}"
        echo -e "${YELLOW}[*] Test artifacts in: $TEST_DIR${NC}"
    else
        echo -e "${RED}[!] Test failed${NC}"
    fi
}

# Print system information
echo -e "\n${YELLOW}=== System Information ===${NC}"
echo -e "${YELLOW}[*] Operating System:${NC}"
cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2

echo -e "\n${YELLOW}[*] CPU Information:${NC}"
grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2

echo -e "\n${YELLOW}[*] Memory Information:${NC}"
free -h | grep "Mem:" | awk '{print "Total: " $2 "  Used: " $3 "  Free: " $4}'

# Ask to run test
echo -e "\n${YELLOW}Would you like to run a quick Frida mode test? (y/N)${NC}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    test_frida_mode
fi

# Print usage information
echo -e "\n${YELLOW}=== AFL++ Frida Mode Usage ===${NC}"
echo -e "To use AFL++ with Frida mode:"
echo -e "1. Basic usage:"
echo -e "   AFL_FRIDA_PERSISTENT_ADDR=<addr> \\"
echo -e "   afl-fuzz -O -i input -o output -F ./target_binary"
echo -e "\n2. Environment variables:"
echo -e "   AFL_FRIDA_DEBUG=1          # Enable debug output"
echo -e "   AFL_FRIDA_PERSISTENT=1     # Enable persistent mode"
echo -e "   AFL_FRIDA_INST_RANGES=...  # Specify instrumentation ranges"
echo -e "   AFL_FRIDA_EXCLUDE_RANGES=... # Specify exclusion ranges"
echo -e "\n3. For Android apps:"
echo -e "   afl-frida -U -o output -i input com.example.app" 