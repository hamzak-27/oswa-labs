#!/bin/bash

# Build Script for CyberLab Container VM Templates
# This script builds all the Docker images for lab environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is available
check_docker() {
    log "Checking Docker availability..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi
    
    success "Docker is available and running"
}

# Build individual image
build_image() {
    local image_name=$1
    local dockerfile_path=$2
    local context_path=$3
    
    log "Building $image_name..."
    
    if [ -f "$dockerfile_path" ]; then
        if docker build -t "$image_name" -f "$dockerfile_path" "$context_path"; then
            success "Built $image_name successfully"
            return 0
        else
            error "Failed to build $image_name"
            return 1
        fi
    else
        error "Dockerfile not found: $dockerfile_path"
        return 1
    fi
}

# Main build function
main() {
    echo "🚀 Starting CyberLab VM Template Image Build"
    echo "=============================================="
    
    # Check prerequisites
    check_docker
    
    # Navigate to the vm-templates directory
    VM_TEMPLATES_DIR="$(dirname "$0")/../docker/vm-templates"
    if [ ! -d "$VM_TEMPLATES_DIR" ]; then
        error "VM templates directory not found: $VM_TEMPLATES_DIR"
        exit 1
    fi
    
    cd "$VM_TEMPLATES_DIR"
    log "Working directory: $(pwd)"
    
    # Track build results
    declare -A build_results
    
    # Build Kali Linux Full Attack Box
    log "Building Kali Linux Attack Box..."
    if build_image "cyberlab/kali-full:latest" "./kali-full/Dockerfile" "./kali-full"; then
        build_results["kali-full"]="success"
    else
        build_results["kali-full"]="failed"
    fi
    
    # Build DVWA
    log "Building DVWA (Damn Vulnerable Web Application)..."
    if build_image "cyberlab/dvwa:latest" "./dvwa/Dockerfile" "./dvwa"; then
        build_results["dvwa"]="success"
    else
        build_results["dvwa"]="failed"
    fi
    
    # Build Ubuntu Server (if exists)
    if [ -d "./ubuntu-server" ]; then
        log "Building Ubuntu Server..."
        if build_image "cyberlab/ubuntu-server:latest" "./ubuntu-server/Dockerfile" "./ubuntu-server"; then
            build_results["ubuntu-server"]="success"
        else
            build_results["ubuntu-server"]="failed"
        fi
    fi
    
    # Build Windows Server (if exists)
    if [ -d "./windows-server" ]; then
        log "Building Windows Server..."
        if build_image "cyberlab/windows-server:latest" "./windows-server/Dockerfile" "./windows-server"; then
            build_results["windows-server"]="success"
        else
            build_results["windows-server"]="failed"
        fi
    fi
    
    # Build Metasploitable (if exists)
    if [ -d "./metasploitable" ]; then
        log "Building Metasploitable..."
        if build_image "cyberlab/metasploitable:latest" "./metasploitable/Dockerfile" "./metasploitable"; then
            build_results["metasploitable"]="success"
        else
            build_results["metasploitable"]="failed"
        fi
    fi
    
    # Print build summary
    echo ""
    echo "=============================================="
    echo "📊 Build Results Summary"
    echo "=============================================="
    
    success_count=0
    failed_count=0
    
    for image in "${!build_results[@]}"; do
        if [ "${build_results[$image]}" = "success" ]; then
            success "$image: Built successfully"
            ((success_count++))
        else
            error "$image: Build failed"
            ((failed_count++))
        fi
    done
    
    echo ""
    echo "Total images: $((success_count + failed_count))"
    echo "Successful: $success_count"
    echo "Failed: $failed_count"
    
    # List built images
    if [ $success_count -gt 0 ]; then
        echo ""
        log "Available CyberLab images:"
        docker images | grep "cyberlab/"
    fi
    
    # Return appropriate exit code
    if [ $failed_count -gt 0 ]; then
        error "Some images failed to build"
        exit 1
    else
        success "All images built successfully!"
        
        echo ""
        echo "🔧 Next Steps:"
        echo "1. Test the VM Service: cd ../../../backend && python test_vm_service.py"
        echo "2. Run database migration to add container fields"
        echo "3. Start the backend API server"
        echo "4. Create a lab session to test container deployment"
        
        exit 0
    fi
}

# Cleanup function for interrupted builds
cleanup() {
    warning "Build interrupted. Cleaning up..."
    # Add any cleanup logic here
    exit 130
}

# Handle SIGINT (Ctrl+C)
trap cleanup SIGINT

# Run main function
main "$@"
