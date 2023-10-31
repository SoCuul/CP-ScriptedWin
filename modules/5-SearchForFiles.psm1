function Search-ForFiles {
    $Extensions = "*.jpg", "*.png", "*.tiff", "*.bmp", "*.gif", "*.mp3", "*.wav", "*.ogg", "*.flac", "*.mp4", "*.mov", "*.mkv", "*.txt", "*.docx", "*.doc", "*.xlsx", "*.csv", "*.pptx", "*.psd", "*.pdf", "*.zip", "*.rar", "*.7z", "*.exe", "*.scr", "*.com", "*.msi"
    $SearchPath = "C:\Users"

    Get-ChildItem -Path $SearchPath -Include $Extensions -Recurse -ErrorAction SilentlyContinue -Force
}