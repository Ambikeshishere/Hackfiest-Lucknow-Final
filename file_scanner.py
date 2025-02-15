import hashlib
import os
import stat
import psutil

try:
    import pefile  # Windows PE analysis
except ImportError:
    pefile = None

# Load known malware hashes from an external file
MALWARE_HASHES = set()
MALWARE_IDX_FILE = "virus.txt"

if os.path.exists(MALWARE_IDX_FILE):
    with open(MALWARE_IDX_FILE, "r") as f:
        MALWARE_HASHES = {line.strip() for line in f if line.strip()}

# Dangerous extensions
DANGEROUS_EXTENSIONS = { ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif", 
                        ".com", ".msi", ".dll", ".sys", ".ps1", ".wsf", ".cpl", ".reg"}

def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file."""
    hash_func = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"⚠️ Error reading file {file_path}: {e}")
        return None  # Return None if file is corrupt

def check_permissions(file_path):
    """Check if the file has unusual permissions."""
    try:
        file_stat = os.stat(file_path)
        if os.name == "nt":  # Windows
            return "🔍 Check manually in Properties -> Security"
        else:  # Linux/macOS
            mode = file_stat.st_mode
            return stat.filemode(mode)
    except Exception as e:
        return f"⚠️ Error checking permissions: {e}"

def check_background_processes(file_name):
    """Check if the file is running as a background process."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if file_name.lower() in proc.info['name'].lower():
            return f"🚨 Running in background! (PID: {proc.info['pid']})"
    return "✅ Not running in background"

def check_file_size(file_path):
    """Check if the file size is 0 or unusually small (less than 1KB)."""
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return "❌ Corrupt (File size is 0 bytes)"
        elif size < 1024:
            return f"⚠️ Suspicious (Unusually small size: {size} bytes)"
        return f"✅ File size is normal ({size} bytes)"
    except Exception as e:
        return f"⚠️ Error checking size: {e}"

def check_pe_structure(file_path):
    """Check if the file is a valid Windows executable using PE headers."""
    if not pefile or not file_path.endswith(".exe"):
        return "🔍 Not an executable or PE analysis not available"

    try:
        pe = pefile.PE(file_path)
        if pe.is_exe():
            return "✅ Valid PE structure"
        else:
            return "❌ Corrupt PE structure"
    except Exception:
        return "❌ Corrupt (Invalid PE headers)"

def check_file_status(file_path):
    """Check if a file is safe, corrupt, or malicious before installation."""
    if not os.path.isfile(file_path):
        print("⚠️ Error: File not found!")
        return
    
    file_hash = calculate_file_hash(file_path)
    file_extension = os.path.splitext(file_path)[1].lower()
    
    print(f"\n🔍 Checking File: {file_path}")
    print(f"🔢 Hash: {file_hash}" if file_hash else "⚠️ Could not calculate hash (Possible corruption)")

    if file_hash in MALWARE_HASHES:
        print(f"🚨 MALICIOUS FILE DETECTED! (Hash: {file_hash})")
    elif file_extension in DANGEROUS_EXTENSIONS:
        print(f"⚠️ WARNING: File has a risky extension ({file_extension})")
    else:
        print(f"✅ File extension is considered safe ({file_extension})")

    print(f"📂 Size Check: {check_file_size(file_path)}")
    print(f"🔐 Permissions: {check_permissions(file_path)}")
    print(f"🕵️ Background Process Check: {check_background_processes(os.path.basename(file_path))}")

    if file_extension == ".exe":
        print(f"🏗 PE Structure: {check_pe_structure(file_path)}")

if __name__ == "__main__":
    file_to_check = input("Enter the file to check: ")
    check_file_status(file_to_check)
