# Generate demo fixtures into ./demo (gitignored, never committed).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/make-demo.ps1
# NOTE: All secret values are randomly generated at runtime for demo purposes only.
# ASCII-only on purpose so it parses cleanly under any Windows code page.

$ErrorActionPreference = "Stop"
$demo = Join-Path $PSScriptRoot "..\demo"
New-Item -ItemType Directory -Force -Path (Join-Path $demo "config"), (Join-Path $demo "src"), (Join-Path $demo "docs") | Out-Null

$rng = New-Object System.Random

function New-RandomString {
    param([int]$Length, [string]$Alphabet)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$sb.Append($Alphabet[$rng.Next($Alphabet.Length)])
    }
    $sb.ToString()
}

$ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$HEX   = "0123456789abcdef"
$LOWER = "abcdefghijklmnopqrstuvwxyz0123456789"

$envLines = @(
    "# secretscan demo fixtures (all values randomly generated, NOT real credentials)",
    "AWS_ACCESS_KEY_ID=AKIA$(New-RandomString 16 $ALNUM)",
    "aws_secret_access_key=$(New-RandomString 40 $ALNUM)",
    "",
    "OPENAI_API_KEY=sk-proj-$(New-RandomString 40 $ALNUM)",
    "",
    "SLACK_BOT_TOKEN=xoxb-$(New-RandomString 32 $ALNUM)",
    "",
    "STRIPE_SECRET_KEY=sk_live_$(New-RandomString 24 $ALNUM)",
    "",
    "GITHUB_TOKEN=ghp_$(New-RandomString 36 $ALNUM)",
    "",
    "TELEGRAM_BOT_TOKEN=9876543210:$(New-RandomString 35 $ALNUM)",
    "",
    "SENDGRID_API_KEY=SG.$(New-RandomString 22 $ALNUM).$(New-RandomString 43 $ALNUM)"
)
Set-Content -Path (Join-Path $demo "config\.env") -Value $envLines -Encoding ASCII

$appLines = @(
    "import os",
    "",
    "# demo: mixed backend service fake credentials (NOT real)",
    "TWILIO_SID = `"AC$(New-RandomString 32 $HEX)`"",
    "TWILIO_API_KEY = `"SK$(New-RandomString 32 $HEX)`"",
    "DISCORD_TOKEN = `"M$(New-RandomString 24 $ALNUM).$(New-RandomString 6 $ALNUM).$(New-RandomString 38 $ALNUM)`"",
    "",
    "# payment secret leaked into source (highest risk)",
    "PAYPAL_TOKEN = 'access_token`$production`$$(New-RandomString 16 $LOWER)_$(New-RandomString 32 $LOWER)'",
    "",
    "# a few cloud provider keys",
    "DO_PAT = `"dop_v1_$(New-RandomString 64 $HEX)`"",
    "GCP_KEY = `"AIza$(New-RandomString 35 $ALNUM)`"",
    "ALIYUN = `"LTAI$(New-RandomString 20 $ALNUM)`""
)
Set-Content -Path (Join-Path $demo "src\app.py") -Value $appLines -Encoding ASCII

$docsLines = @(
    "# setup docs with placeholder examples (these get filtered as false positives)",
    "OPENAI_API_KEY=sk-00000000000000000000000000000000",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
)
Set-Content -Path (Join-Path $demo "docs\setup.example.md") -Value $docsLines -Encoding ASCII

Write-Host "Demo fixtures generated in: $demo"
Write-Host "Run: .\target\release\secretscan.exe --format all -o secretscan-report demo"
