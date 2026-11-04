# Test double: defines Invoke-RestMethod (functions win over cmdlets in
# PowerShell command resolution) serving tests/fixtures/fake-api.json, then
# runs the real collector. Usage: pwsh -File fake-pwsh-api.ps1 <collector.ps1> <outdir>
param([string]$Collector, [string]$OutDir)
$global:CfarFakeApi = Get-Content -Raw $env:FAKE_API | ConvertFrom-Json -AsHashtable

function global:Invoke-RestMethod {
    param([string]$Uri, $Headers, [string]$Method, [int]$TimeoutSec)
    if ($Method -ne "Get") { throw "fake API: non-GET method $Method" }
    $path = ([Uri]$Uri).AbsolutePath -replace '^/client/v4', ''
    $entry = $global:CfarFakeApi[$path]
    if ($null -eq $entry) { $entry = @{ status = 404; body = @{ success = $false; errors = @(@{ message = "not found" }) } } }
    if ($entry.status -ne 200) {
        $ex = [System.Exception]::new("HTTP $($entry.status)")
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $entry.status })
        throw $ex
    }
    # Round-trip through JSON so the collector sees PSCustomObjects, like the real cmdlet returns.
    return ($entry.body | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

& $Collector -OutputDir $OutDir
