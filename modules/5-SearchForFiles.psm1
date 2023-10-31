function Search-ForFiles {
    $Extensions = "*.jpg", "*.jpeg", "*.png", "*.tiff", "*.bmp", "*.gif", "*.mp3", "*.wav", "*.ogg", "*.flac", "*.mp4", "*.mov", "*.mkv", "*.txt", "*.docx", "*.doc", "*.xlsx", "*.csv", "*.pptx", "*.psd", "*.pdf", "*.zip", "*.rar", "*.7z", "*.exe", "*.scr", "*.com", "*.msi", "*.bat"
    $SearchPath = "C:\Users"

    Get-ChildItem -Path $SearchPath -Include $Extensions -Recurse -ErrorAction SilentlyContinue -Force
}