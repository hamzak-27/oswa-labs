#!/usr/bin/env pwsh

# OSWA Labs Deployment Script
# This script deploys the complete OSWA lab environment

param(
    [Parameter(Mandatory=$false)]
    [switch]$Clean = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildOnly = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild = $false
)

Write-Host "🚀 OSWA Labs Deployment Script" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Configuration
$COMPOSE_FILE = "docker-compose.production.yml"
$PROJECT_NAME = "oswa-labs"

# Clean previous deployment if requested
if ($Clean) {
    Write-Host "🧹 Cleaning previous deployment..." -ForegroundColor Yellow
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v --remove-orphans
    docker system prune -f
    Write-Host "✅ Cleanup completed" -ForegroundColor Green
}

# Create required directories
Write-Host "📁 Creating required directories..." -ForegroundColor Blue
$directories = @(
    "database",
    "nginx",
    "jwt-attacks-lab/keys",
    "lab-management-api/uploads",
    "xss-lab/uploads",
    "jwt-attacks-lab/uploads"
)

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force
        Write-Host "   Created: $dir" -ForegroundColor Gray
    }
}

# Create Nginx configuration if it doesn't exist
if (!(Test-Path "nginx/nginx.conf")) {
    Write-Host "🔧 Creating Nginx configuration..." -ForegroundColor Blue
    @"
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    upstream dashboard {
        server oswa-dashboard:3000;
    }
    
    upstream api {
        server oswa-lab-management-api:8000;
    }
    
    upstream xss-lab {
        server oswa-xss-lab-backend:5000;
    }
    
    upstream jwt-lab {
        server oswa-jwt-lab-backend:5001;
    }
    
    upstream sql-lab {
        server oswa-sql-lab-backend:3000;
    }
    
    server {
        listen 80;
        server_name localhost;
        
        # Dashboard
        location / {
            proxy_pass http://dashboard;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
        
        # API
        location /api/ {
            proxy_pass http://api/;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
        
        # Labs
        location /labs/xss/ {
            proxy_pass http://xss-lab/;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
        
        location /labs/jwt/ {
            proxy_pass http://jwt-lab/;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
        
        location /labs/sql/ {
            proxy_pass http://sql-lab/;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        }
    }
}
"@ | Out-File -FilePath "nginx/nginx.conf" -Encoding UTF8
    Write-Host "✅ Nginx configuration created" -ForegroundColor Green
}

# Create Dockerfiles for services that need them
function Create-Dockerfile {
    param($Service, $Content)
    
    $dockerfilePath = "$Service/Dockerfile"
    if (!(Test-Path $dockerfilePath)) {
        Write-Host "🐳 Creating Dockerfile for $Service..." -ForegroundColor Blue
        $Content | Out-File -FilePath $dockerfilePath -Encoding UTF8
        Write-Host "✅ Dockerfile created for $Service" -ForegroundColor Green
    }
}

# Dashboard Dockerfile
Create-Dockerfile "oswa-dashboard" @"
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
"@

# Lab Management API Dockerfile
Create-Dockerfile "lab-management-api" @"
FROM node:18-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN mkdir -p /app/uploads /app/logs
RUN chmod 755 /app/uploads /app/logs
EXPOSE 8000
CMD ["npm", "start"]
"@

if ($BuildOnly) {
    Write-Host "🔨 Building images only..." -ForegroundColor Yellow
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME build
    Write-Host "✅ Build completed" -ForegroundColor Green
    exit 0
}

# Start deployment
Write-Host "🚀 Starting OSWA Labs deployment..." -ForegroundColor Cyan

if ($SkipBuild) {
    Write-Host "⚡ Starting services (skipping build)..." -ForegroundColor Yellow
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d --no-build
} else {
    Write-Host "🔨 Building and starting services..." -ForegroundColor Yellow
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d --build
}

# Wait for services to start
Write-Host "⏳ Waiting for services to initialize..." -ForegroundColor Blue
Start-Sleep -Seconds 30

# Health check
Write-Host "🔍 Performing health checks..." -ForegroundColor Blue

$services = @{
    "Lab Management API" = "http://localhost:8000/health"
    "Dashboard" = "http://localhost:3002"
    "XSS Lab" = "http://localhost:5000/health"
    "JWT Lab" = "http://localhost:5001/health"
}

foreach ($service in $services.GetEnumerator()) {
    try {
        $response = Invoke-WebRequest -Uri $service.Value -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "   ✅ $($service.Name) - OK" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ $($service.Name) - Status $($response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ $($service.Name) - Failed" -ForegroundColor Red
    }
}

# Display status
Write-Host ""
Write-Host "🎉 OSWA Labs Deployment Complete!" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "🌐 Access URLs:" -ForegroundColor White
Write-Host "   Dashboard:     http://localhost:3002" -ForegroundColor Gray
Write-Host "   API:           http://localhost:8000" -ForegroundColor Gray
Write-Host "   XSS Lab:       http://localhost:5000" -ForegroundColor Gray
Write-Host "   JWT Lab:       http://localhost:5001" -ForegroundColor Gray
Write-Host "   SQL Lab:       http://localhost:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "👤 Default Login Credentials:" -ForegroundColor White
Write-Host "   Admin:    admin@oswa.local / admin123" -ForegroundColor Gray
Write-Host "   Student:  student@oswa.local / student123" -ForegroundColor Gray
Write-Host ""
Write-Host "📊 Container Status:" -ForegroundColor White
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps

Write-Host ""
Write-Host "🔗 Quick Commands:" -ForegroundColor White
Write-Host "   View logs:     docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f" -ForegroundColor Gray
Write-Host "   Stop all:      docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down" -ForegroundColor Gray
Write-Host "   Restart:       docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME restart" -ForegroundColor Gray
Write-Host ""
Write-Host "🚀 Happy hacking! The OSWA labs are ready for penetration testing practice." -ForegroundColor Green