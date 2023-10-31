function Show-FileShares {
    $Filter = "Type = 0 And Description != 'Default Share' And Name != 'ADMIN$' And Name != 'IPC$'"

    Write-Output "Listing non-standard file shares:"
    Write-Output "(This may take a few seconds)"
    Write-Output ""

    Get-CimInstance Win32_Share -Filter $Filter

    timeout 5 -Nobreak | Out-Null
}