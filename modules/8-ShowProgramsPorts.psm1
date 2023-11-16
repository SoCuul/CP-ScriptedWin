function Show-ProgramsPorts {
    # Map sysinternals WebDAV share
    net use X: https://live.sysinternals.com

    # Run tcpview
    X:\tcpview64.exe

    # Force delete network share from system
    Write-Output "y" | net use X: /del
}