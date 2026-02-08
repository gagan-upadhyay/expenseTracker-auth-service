#!/usr/bin/env pwsh
# FCM Integration Quick Test Script
# Usage: .\test-fcm.ps1

$API="http://localhost:5000/api/v1/auth"
$HEADERS = @{
    "Content-Type" = "application/json"
}

Write-Host "`n=== FCM Integration Quick Tests ===" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "`n[1/7] Health Check..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5000" -ErrorAction Stop
    Write-Host "✅ Server is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Server not responding. Run: npm run dev" -ForegroundColor Red
    exit 1
}

# Test 2: Register User
Write-Host "`n[2/7] Registering test user..." -ForegroundColor Yellow
$registerBody = @{
    username = "testuser$(Get-Random)"
    email = "test$(Get-Random)@example.com"
    password = "TestPassword@123"
} | ConvertTo-Json

try {
    $registerResponse = Invoke-WebRequest -Uri "$API/register" `
        -Method POST `
        -Headers $HEADERS `
        -Body $registerBody `
        -ResponseHeadersVariable "responseHeaders" `
        -ErrorAction Stop
    
    $userData = $registerResponse.Content | ConvertFrom-Json
    Write-Host "✅ User registered: $($userData.user.email)" -ForegroundColor Green
} catch {
    Write-Host "❌ Registration failed: $_" -ForegroundColor Red
    exit 1
}

# Extract cookies from response (if present)
$cookies = @()

# Test 3: Login
Write-Host "`n[3/7] Logging in..." -ForegroundColor Yellow
$loginBody = @{
    email = $userData.user.email
    password = "TestPassword@123"
} | ConvertTo-Json

try {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $loginResponse = Invoke-WebRequest -Uri "$API/login" `
        -Method POST `
        -Headers $HEADERS `
        -Body $loginBody `
        -WebSession $session `
        -ErrorAction Stop
    
    $loginData = $loginResponse.Content | ConvertFrom-Json
    Write-Host "✅ Login successful for: $($loginData.user.email)" -ForegroundColor Green
    Write-Host "   Cookies stored in session" -ForegroundColor Gray
} catch {
    Write-Host "❌ Login failed: $_" -ForegroundColor Red
    exit 1
}

# Test 4: Register FCM Token
Write-Host "`n[4/7] Registering FCM token..." -ForegroundColor Yellow
$tokenBody = @{
    fcmToken = "test-token-$(Get-Random)"
} | ConvertTo-Json

try {
    $tokenResponse = Invoke-WebRequest -Uri "$API/fcm/register-token" `
        -Method POST `
        -Headers $HEADERS `
        -Body $tokenBody `
        -WebSession $session `
        -ErrorAction Stop
    
    Write-Host "✅ FCM token registered" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Token registration failed (might need valid token): $_" -ForegroundColor Yellow
}

# Test 5: Get FCM Token
Write-Host "`n[5/7] Retrieving FCM token..." -ForegroundColor Yellow
try {
    $getTokenResponse = Invoke-WebRequest -Uri "$API/fcm/token" `
        -Method GET `
        -Headers $HEADERS `
        -WebSession $session `
        -ErrorAction Stop
    
    $tokenData = $getTokenResponse.Content | ConvertFrom-Json
    Write-Host "✅ Token retrieved: $($tokenData.fcmToken)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  No token found yet" -ForegroundColor Yellow
}

# Test 6: Login Again (Triggers FCM Notification)
Write-Host "`n[6/7] Login again to test FCM notification..." -ForegroundColor Yellow
try {
    $loginResponse2 = Invoke-WebRequest -Uri "$API/login" `
        -Method POST `
        -Headers $HEADERS `
        -Body $loginBody `
        -WebSession $session `
        -ErrorAction Stop
    
    Write-Host "✅ Login successful (check server logs for FCM notification)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Second login failed: $_" -ForegroundColor Yellow
}

# Test 7: Logout
Write-Host "`n[7/7] Logging out..." -ForegroundColor Yellow
try {
    $logoutResponse = Invoke-WebRequest -Uri "$API/logout" `
        -Method POST `
        -Headers $HEADERS `
        -WebSession $session `
        -ErrorAction Stop
    
    Write-Host "✅ Logout successful (token cleanup triggered)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Logout failed: $_" -ForegroundColor Yellow
}

Write-Host "`n=== All tests completed ===" -ForegroundColor Cyan
Write-Host "📝 Check server logs in npm terminal for FCM activity" -ForegroundColor Gray
Write-Host "📖 For detailed testing, see: POSTMAN_TESTING.md" -ForegroundColor Gray
