function Show-ProgramsPorts {
    # TODO: fix this literally not working at all (the network name cannot be found)
    # Map sysinternals WebDAV share
    net use X: https://live.sysinternals.com

    # Run tcpview
    X:\tcpview64.exe

    # Force delete network share from system
    Write-Output "y" | net use X: /del
}
