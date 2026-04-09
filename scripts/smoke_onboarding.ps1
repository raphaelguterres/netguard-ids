param(
    [string]$BaseUrl = "http://127.0.0.1:5000"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-WebRequestCompat {
    param(
        [string]$Url,
        [bool]$AllowRedirect = $false
    )

    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $request.Method = "GET"
    $request.AllowAutoRedirect = $AllowRedirect
    $request.Timeout = 15000

    try {
        $response = [System.Net.HttpWebResponse]$request.GetResponse()
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response -is [System.Net.HttpWebResponse]) {
            $response = [System.Net.HttpWebResponse]$_.Exception.Response
        }
        else {
            throw
        }
    }

    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    try {
        $body = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }

    return [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Headers    = $response.Headers
        Body       = $body
        Response   = $response
    }
}

function Invoke-JsonRequestCompat {
    param(
        [string]$Url,
        [string]$Method = "POST",
        [string]$JsonBody
    )

    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $request.Method = $Method
    $request.ContentType = "application/json"
    $request.Timeout = 15000

    if ($JsonBody) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try {
            $stream.Write($bytes, 0, $bytes.Length)
        }
        finally {
            $stream.Dispose()
        }
    }

    try {
        $response = [System.Net.HttpWebResponse]$request.GetResponse()
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response -is [System.Net.HttpWebResponse]) {
            $response = [System.Net.HttpWebResponse]$_.Exception.Response
        }
        else {
            throw
        }
    }

    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    try {
        $body = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }

    return [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Headers    = $response.Headers
        Body       = $body
        Response   = $response
    }
}

Write-Step "Checando servidor em $BaseUrl"
try {
    $health = Invoke-RestMethod "$BaseUrl/health"
}
catch {
    throw "Servidor indisponivel em $BaseUrl. Suba antes com: python app.py"
}

Write-Host ("Health OK: " + ($health | ConvertTo-Json -Compress)) -ForegroundColor Green

$stamp = Get-Date -Format "yyyyMMddHHmmss"
$bodyObject = @{
    name    = "Smoke Test $stamp"
    email   = "smoke.$stamp@example.com"
    company = "Smoke Co"
    plan    = "pro"
}
$bodyJson = $bodyObject | ConvertTo-Json

Write-Step "Criando trial"
$trial = Invoke-RestMethod `
    -Uri "$BaseUrl/trial" `
    -Method Post `
    -ContentType "application/json" `
    -Body $bodyJson

Assert-True ($null -ne $trial.token) "Resposta do /trial nao trouxe token."
Assert-True ($trial.token.StartsWith("ng_")) "Token retornado nao comeca com ng_."
Assert-True ($null -ne $trial.welcome_url) "Resposta do /trial nao trouxe welcome_url."
Assert-True ($trial.welcome_url -match "/welcome\?onboarding=") "welcome_url nao usa ticket opaco."
Assert-True (-not ($trial.welcome_url -match "token=")) "welcome_url ainda expõe token."
Assert-True (-not ($trial.welcome_url -match "email=")) "welcome_url ainda expõe email."
Assert-True (-not $trial.welcome_url.Contains($trial.token)) "welcome_url contem o token em plaintext."

Write-Host ("Tenant criado: " + $trial.tenant_id) -ForegroundColor Green
Write-Host ("Token prefix: " + $trial.token.Substring(0, [Math]::Min(12, $trial.token.Length)) + "...") -ForegroundColor Yellow
Write-Host ("Welcome URL: " + $trial.welcome_url) -ForegroundColor Yellow

Write-Step "Consumindo welcome ticket pela primeira vez"
$response1 = Invoke-WebRequestCompat -Url $trial.welcome_url

Assert-True ($response1.StatusCode -eq 200) "Primeira chamada ao /welcome nao retornou 200."
Assert-True ($response1.Body.Contains($trial.token)) "Pagina welcome nao exibiu o token."
Assert-True (($response1.Headers["Cache-Control"] -match "no-store")) "Cache-Control nao veio com no-store."
Assert-True (($response1.Headers["Referrer-Policy"] -match "no-referrer")) "Referrer-Policy nao veio como no-referrer."

Write-Host "Primeira chamada OK: token exibido e sem cache." -ForegroundColor Green

Write-Step "Tentando reutilizar o mesmo welcome ticket"
$response2 = Invoke-WebRequestCompat -Url $trial.welcome_url
$location = [string]$response2.Headers["Location"]

$isRedirect = ($response2.StatusCode -in @(302, 303, 307))

Assert-True $isRedirect "Segunda chamada ao /welcome deveria redirecionar."
Assert-True ($location -match "/pricing\?error=welcome_expired") "Segunda chamada nao expirou como esperado."

Write-Host "Segunda chamada OK: ticket de uso unico expirou." -ForegroundColor Green

Write-Step "Validando free preview temporario"
$previewBodyJson = @{ token = $trial.token } | ConvertTo-Json
$previewResponse = Invoke-JsonRequestCompat `
    -Url "$BaseUrl/api/auth/free-preview" `
    -JsonBody $previewBodyJson

Assert-True ($previewResponse.StatusCode -eq 200) "POST /api/auth/free-preview nao retornou 200."
$previewJson = $previewResponse.Body | ConvertFrom-Json
$setCookie = [string]$previewResponse.Headers["Set-Cookie"]

Assert-True ($previewJson.valid -eq $true) "Free preview nao foi validado."
Assert-True ($previewJson.redirect_to -eq "/dashboard") "Free preview nao apontou para /dashboard."
Assert-True ($previewJson.minutes -ge 1) "Free preview nao retornou duracao valida."
Assert-True ($setCookie -match "netguard_preview_mode=free") "Cookie netguard_preview_mode nao foi definido."
Assert-True ($setCookie -match "netguard_preview_expires=") "Cookie netguard_preview_expires nao foi definido."

Write-Host "Free preview OK: sessao curta e cookies temporarios emitidos." -ForegroundColor Green

Write-Step "Smoke test concluido"
Write-Host "Tudo certo: trial seguro, welcome_url opaca, token de uso unico, pagina sem cache e free preview temporario." -ForegroundColor Green
