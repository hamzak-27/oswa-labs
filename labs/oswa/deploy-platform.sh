#!/bin/bash

# OSWA Platform Deployment Script
# This script deploys the complete OSWA cybersecurity lab platform

set -e

echo "🚀 Starting OSWA Platform Deployment..."
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_status "Checking system dependencies..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "All dependencies are satisfied"
}

# Initialize VPN server
setup_vpn() {
    print_status "Setting up OpenVPN server..."
    
    # Create VPN data directories
    mkdir -p vpn-server/data
    mkdir -p vpn-server/configs
    
    # Generate VPN server configurations if they don't exist
    if [ ! -f "vpn-server/configs/server.conf" ]; then
        print_status "Generating VPN server configuration..."
        
        cat > vpn-server/configs/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Lab network routes
push "route 172.20.1.0 255.255.255.0"
push "route 172.20.2.0 255.255.255.0"
push "route 172.20.3.0 255.255.255.0"

keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1

# Management interface
management 0.0.0.0 7505
management-client-auth
EOF
        print_success "VPN server configuration generated"
    fi
}

# Build all containers
build_containers() {
    print_status "Building all container images..."
    
    # Build in specific order to handle dependencies
    print_status "Building VPN server..."
    docker-compose -f docker-compose.platform.yml build vpn-server
    
    print_status "Building Lab Management API..."
    docker-compose -f docker-compose.platform.yml build lab-management-api
    
    print_status "Building Dashboard..."
    docker-compose -f docker-compose.platform.yml build oswa-dashboard
    
    print_status "Building lab containers..."
    docker-compose -f docker-compose.platform.yml build xss-backend xss-frontend
    docker-compose -f docker-compose.platform.yml build jwt-backend jwt-frontend
    docker-compose -f docker-compose.platform.yml build sql-webapp
    
    print_success "All containers built successfully"
}

# Initialize databases
init_databases() {
    print_status "Initializing databases..."
    
    # Start database containers first
    docker-compose -f docker-compose.platform.yml up -d mongodb redis
    docker-compose -f docker-compose.platform.yml up -d xss-mongodb jwt-mongodb sql-mysql
    
    print_status "Waiting for databases to be ready..."
    sleep 30
    
    print_success "Databases initialized"
}

# Start core services
start_core_services() {
    print_status "Starting core platform services..."
    
    # Start VPN server
    docker-compose -f docker-compose.platform.yml up -d vpn-server
    
    # Start API and dashboard
    docker-compose -f docker-compose.platform.yml up -d lab-management-api oswa-dashboard
    
    # Wait for services to be ready
    print_status "Waiting for core services to start..."
    sleep 15
    
    print_success "Core services started"
}

# Start lab services (initially stopped for on-demand startup)
prepare_lab_services() {
    print_status "Preparing lab services (will be started on-demand)..."
    
    # We don't start the lab services here - they will be started via API calls
    print_success "Lab services prepared for on-demand startup"
}

# Create initial admin user
create_admin_user() {
    print_status "Creating initial admin user..."
    
    # This would typically involve API calls to create the admin user
    # For now, we'll just note that this should be done
    print_warning "Please create admin user through the dashboard UI after deployment"
}

# Display access information
show_access_info() {
    echo ""
    echo "🎉 OSWA Platform Deployment Complete!"
    echo "======================================"
    echo ""
    print_success "Platform Services:"
    echo "  📊 Dashboard:        http://localhost:3002"
    echo "  🔧 API:              http://localhost:8000"
    echo "  📚 API Docs:         http://localhost:8000/api/docs"
    echo "  ❤️  Health Check:    http://localhost:8000/health"
    echo ""
    
    print_success "Lab Access (when running):"
    echo "  🕷️  XSS Lab:          http://localhost:3000 (dev) | VPN: 172.20.1.10:3000"
    echo "  🔑 JWT Lab:          http://localhost:3001 (dev) | VPN: 172.20.2.10:3000"
    echo "  💉 SQL Injection:    http://localhost:61505 (dev) | VPN: 172.20.3.10:80"
    echo ""
    
    print_success "VPN Server:"
    echo "  🌐 OpenVPN:          UDP port 1194"
    echo "  ⚙️  Management:       port 7505"
    echo ""
    
    print_warning "Next Steps:"
    echo "  1. Access the dashboard at http://localhost:3002"
    echo "  2. Create your admin account"
    echo "  3. Generate VPN certificates from the dashboard"
    echo "  4. Start individual labs as needed"
    echo "  5. Connect via VPN to access lab networks"
    echo ""
}

# Check system status
check_status() {
    print_status "Checking platform status..."
    
    echo ""
    echo "Container Status:"
    echo "=================="
    docker-compose -f docker-compose.platform.yml ps
    
    echo ""
    echo "Network Status:"
    echo "==============="
    docker network ls | grep oswa || print_warning "OSWA networks not found"
    
    echo ""
}

# Main deployment process
main() {
    echo "Select deployment option:"
    echo "1. Full deployment (recommended for first-time setup)"
    echo "2. Quick start (assumes images are built)"
    echo "3. Status check only"
    echo "4. Stop all services"
    echo ""
    
    read -p "Enter your choice (1-4): " choice
    
    case $choice in
        1)
            print_status "Starting full deployment..."
            check_dependencies
            setup_vpn
            build_containers
            init_databases
            start_core_services
            prepare_lab_services
            create_admin_user
            check_status
            show_access_info
            ;;
        2)
            print_status "Starting quick deployment..."
            check_dependencies
            init_databases
            start_core_services
            prepare_lab_services
            check_status
            show_access_info
            ;;
        3)
            check_status
            ;;
        4)
            print_status "Stopping all services..."
            docker-compose -f docker-compose.platform.yml down
            print_success "All services stopped"
            ;;
        *)
            print_error "Invalid choice. Exiting."
            exit 1
            ;;
    esac
}

# Run main function
main