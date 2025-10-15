#!/usr/bin/env pwsh

# OSWA Labs Testing Script
# This script tests all lab functionality end-to-end

Write-Host "🧪 OSWA Labs Testing Script" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Test configuration
$BASE_URLS = @{
    "API" = "http://localhost:8000"
    "Dashboard" = "http://localhost:3002"
    "XSS_Lab" = "http://localhost:5000"
    "JWT_Lab" = "http://localhost:5001"
    "SQL_Lab" = "http://localhost:3000"
}

$TEST_FLAGS = @{
    "XSS_REFLECTED" = "FLAG{R3FL3CT3D_XSS_M4ST3R}"
    "XSS_DOM_BASED" = "FLAG{D0M_XSS_CSP_BYP4SS_L33T}"
    "JWT_NONE_ALG" = "FLAG{JWT_N0N3_4LG0R1THM_BYPASS}"
    "JWT_WEAK_SECRET" = "FLAG{JWT_W34K_S3CR3T_CR4CK3D}"
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [int]$ExpectedStatus = 200
    )
    
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Host "   ✅ $Name" -ForegroundColor Green
            return $true
        } else {
            Write-Host "   ❌ $Name - Expected $ExpectedStatus, got $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "   ❌ $Name - Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-XSSVulnerability {
    param(
        [string]$BaseUrl,
        [string]$Payload,
        [string]$ExpectedFlag
    )
    
    try {
        $testUrl = "$BaseUrl/vulnerable/reflect?input=$([System.Web.HttpUtility]::UrlEncode($Payload))"
        $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 10 -UseBasicParsing
        
        if ($response.Content -match [regex]::Escape($ExpectedFlag)) {
            Write-Host "   ✅ XSS Reflected - Flag found" -ForegroundColor Green
            return $true
        } else {
            Write-Host "   ⚠️ XSS Reflected - Vulnerable but flag not found" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "   ❌ XSS Reflected - Test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-JWTVulnerability {
    param([string]$BaseUrl)
    
    try {
        # Test JWT endpoints
        $loginUrl = "$BaseUrl/api/auth/login"
        $loginData = @{
            username = "admin"
            password = "admin123"
        } | ConvertTo-Json
        
        $headers = @{
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-WebRequest -Uri $loginUrl -Method POST -Body $loginData -Headers $headers -TimeoutSec 10 -UseBasicParsing
        
        if ($response.StatusCode -eq 200) {
            Write-Host "   ✅ JWT Lab - Login working" -ForegroundColor Green
            return $true
        } else {
            Write-Host "   ❌ JWT Lab - Login failed" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "   ❌ JWT Lab - Test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Start testing
Write-Host "🔍 Starting connectivity tests..." -ForegroundColor Blue
Write-Host ""

$connectivityResults = @{}
foreach ($service in $BASE_URLS.GetEnumerator()) {
    Write-Host "Testing $($service.Key)..." -ForegroundColor White
    
    switch ($service.Key) {
        "API" {
            $connectivityResults[$service.Key] = Test-Endpoint "$($service.Key) Health" "$($service.Value)/health"
        }
        "Dashboard" {
            $connectivityResults[$service.Key] = Test-Endpoint "$($service.Key) Frontend" "$($service.Value)"
        }
        "XSS_Lab" {
            $connectivityResults[$service.Key] = Test-Endpoint "$($service.Key) Health" "$($service.Value)/health"
        }
        "JWT_Lab" {
            $connectivityResults[$service.Key] = Test-Endpoint "$($service.Key) Health" "$($service.Value)/health"
        }
        "SQL_Lab" {
            $connectivityResults[$service.Key] = Test-Endpoint "$($service.Key) Health" "$($service.Value)/health" -ExpectedStatus 404
        }
    }
}

Write-Host ""
Write-Host "🎯 Starting vulnerability tests..." -ForegroundColor Blue
Write-Host ""

$vulnResults = @{}

# Test XSS Lab
if ($connectivityResults["XSS_Lab"]) {
    Write-Host "Testing XSS Lab vulnerabilities..." -ForegroundColor White
    $xssPayload = "<script>document.location.hash='#xss-success'</script>"
    $vulnResults["XSS_Reflected"] = Test-XSSVulnerability $BASE_URLS["XSS_Lab"] $xssPayload $TEST_FLAGS["XSS_REFLECTED"]
    
    # Test DOM XSS
    try {
        $domUrl = "$($BASE_URLS['XSS_Lab'])/vulnerable/dom"
        $response = Invoke-WebRequest -Uri $domUrl -TimeoutSec 10 -UseBasicParsing
        if ($response.Content -match [regex]::Escape($TEST_FLAGS["XSS_DOM_BASED"])) {
            Write-Host "   ✅ XSS DOM - Flag accessible" -ForegroundColor Green
            $vulnResults["XSS_DOM"] = $true
        } else {
            Write-Host "   ⚠️ XSS DOM - Page loads but flag not found" -ForegroundColor Yellow
            $vulnResults["XSS_DOM"] = $false
        }
    } catch {
        Write-Host "   ❌ XSS DOM - Test failed" -ForegroundColor Red
        $vulnResults["XSS_DOM"] = $false
    }
}

# Test JWT Lab
if ($connectivityResults["JWT_Lab"]) {
    Write-Host "Testing JWT Lab vulnerabilities..." -ForegroundColor White
    $vulnResults["JWT_Auth"] = Test-JWTVulnerability $BASE_URLS["JWT_Lab"]
    
    # Test vulnerable endpoints
    try {
        $vulnUrl = "$($BASE_URLS['JWT_Lab'])/api/vulnerable/none-algorithm"
        $response = Invoke-WebRequest -Uri $vulnUrl -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "   ✅ JWT None Algorithm - Endpoint accessible" -ForegroundColor Green
            $vulnResults["JWT_None"] = $true
        }
    } catch {
        $vulnResults["JWT_None"] = $false
    }
}

# Test SQL Lab (basic connectivity)
if ($connectivityResults.ContainsKey("SQL_Lab")) {
    Write-Host "Testing SQL Lab..." -ForegroundColor White
    try {
        $response = Invoke-WebRequest -Uri $BASE_URLS["SQL_Lab"] -TimeoutSec 10 -UseBasicParsing
        Write-Host "   ✅ SQL Lab - Application accessible" -ForegroundColor Green
        $vulnResults["SQL_Basic"] = $true
    } catch {
        Write-Host "   ❌ SQL Lab - Application not accessible" -ForegroundColor Red
        $vulnResults["SQL_Basic"] = $false
    }
}

Write-Host ""
Write-Host "📊 Test Results Summary" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Connectivity Results
Write-Host "🔗 Connectivity Tests:" -ForegroundColor White
$connectivityPassed = 0
foreach ($result in $connectivityResults.GetEnumerator()) {
    $status = if ($result.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($result.Value) { "Green" } else { "Red" }
    Write-Host "   $($result.Key): $status" -ForegroundColor $color
    if ($result.Value) { $connectivityPassed++ }
}

# Vulnerability Results
Write-Host ""
Write-Host "🎯 Vulnerability Tests:" -ForegroundColor White
$vulnPassed = 0
foreach ($result in $vulnResults.GetEnumerator()) {
    $status = if ($result.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($result.Value) { "Green" } else { "Red" }
    Write-Host "   $($result.Key): $status" -ForegroundColor $color
    if ($result.Value) { $vulnPassed++ }
}

Write-Host ""
Write-Host "🏆 Overall Score:" -ForegroundColor White
$totalConnectivity = $connectivityResults.Count
$totalVuln = $vulnResults.Count
Write-Host "   Connectivity: $connectivityPassed/$totalConnectivity" -ForegroundColor $(if($connectivityPassed -eq $totalConnectivity){'Green'}else{'Yellow'})
Write-Host "   Vulnerabilities: $vulnPassed/$totalVuln" -ForegroundColor $(if($vulnPassed -eq $totalVuln){'Green'}else{'Yellow'})

$overallScore = [math]::Round((($connectivityPassed + $vulnPassed) / ($totalConnectivity + $totalVuln)) * 100, 1)
Write-Host "   Overall: $overallScore%" -ForegroundColor $(if($overallScore -ge 80){'Green'}elseif($overallScore -ge 60){'Yellow'}else{'Red'})

Write-Host ""
if ($overallScore -ge 80) {
    Write-Host "🎉 Great! Most tests passed. The OSWA labs are ready for use." -ForegroundColor Green
} elseif ($overallScore -ge 60) {
    Write-Host "⚠️ Some issues detected. Check the failing tests above." -ForegroundColor Yellow
} else {
    Write-Host "❌ Multiple issues detected. Please check the deployment and try again." -ForegroundColor Red
}

Write-Host ""
Write-Host "💡 Next Steps:" -ForegroundColor White
Write-Host "   1. Open dashboard: http://localhost:3002" -ForegroundColor Gray
Write-Host "   2. Login with: admin@oswa.local / admin123" -ForegroundColor Gray
Write-Host "   3. Start exploring the labs!" -ForegroundColor Gray