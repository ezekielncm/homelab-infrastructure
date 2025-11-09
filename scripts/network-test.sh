#!/bin/bash

###############################################################################
# Homelab Infrastructure - Network Test Script
# Description: Test connectivity and services
# Author: Shadow
# Version: 1.0
###############################################################################

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test counter
PASSED=0
FAILED=0

# Function to run test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" &>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAILED++))
        return 1
    fi
}

echo "=============================================="
echo "Homelab Network Tests"
echo "=============================================="
echo ""

# Test 1: Network interfaces
echo "=== Network Interface Tests ==="
run_test "Network interface exists" "ip link show enp0s3"
run_test "IP address assigned" "ip addr show enp0s3 | grep 'inet 192.168.10.10'"
echo ""

# Test 2: Gateway connectivity
echo "=== Gateway Connectivity ==="
run_test "Ping pfSense gateway" "ping -c 3 -W 2 192.168.10.1"
echo ""

# Test 3: Internal network
echo "=== Internal Network ==="
run_test "Ping Windows Server" "ping -c 3 -W 2 192.168.10.20"
run_test "Ping Kali Linux" "ping -c 3 -W 2 192.168.10.30"
echo ""

# Test 4: Internet connectivity
echo "=== Internet Connectivity ==="
run_test "Ping Google DNS" "ping -c 3 -W 2 8.8.8.8"
run_test "DNS resolution" "nslookup google.com"
run_test "HTTP connectivity" "curl -s -o /dev/null -w '%{http_code}' https://google.com | grep -q 200"
echo ""

# Test 5: DNS resolution (internal)
echo "=== DNS Resolution (Internal) ==="
run_test "Resolve firewall.homelab.local" "nslookup firewall.homelab.local 192.168.10.20"
run_test "Resolve dc.homelab.local" "nslookup dc.homelab.local 192.168.10.20"
echo ""

# Test 6: Services
echo "=== Service Status ==="
run_test "SSH service running" "systemctl is-active sshd"
run_test "Fail2Ban service running" "systemctl is-active fail2ban"
run_test "UFW service running" "systemctl is-active ufw"
run_test "Rsyslog service running" "systemctl is-active rsyslog"
echo ""

# Test 7: Security
echo "=== Security Checks ==="
run_test "UFW is enabled" "ufw status | grep -q 'Status: active'"
run_test "SSH on port 2222" "ss -tlnp | grep -q ':2222'"
run_test "Fail2Ban jails active" "fail2ban-client status | grep -q 'sshd'"
echo ""

# Test 8: Port scan (basic)
echo "=== Port Scan (Self) ==="
if command -v nmap &> /dev/null; then
    echo "Running nmap scan..."
    nmap -p- 192.168.10.10 2>/dev/null | grep "open" || echo "No unexpected ports open ✓"
else
    echo -e "${YELLOW}nmap not installed, skipping${NC}"
fi
echo ""

# Summary
echo "=============================================="
echo "Test Summary"
echo "=============================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! Network is healthy.${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check configuration.${NC}"
    exit 1
fi
