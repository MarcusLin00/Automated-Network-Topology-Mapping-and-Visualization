import os
import time
from pathlib import Path

def create_sensitive_file(test_dir: str, index: int, content: str):
    """Create a file with sensitive content."""
    file_path = Path(test_dir) / f"sensitive_file_{index}.txt"
    with open(file_path, "w") as f:
        f.write(content)
    return file_path

def modify_file(file_path: Path):
    """Modify an existing file."""
    with open(file_path, "a") as f:
        f.write("\nAdditional confidential information")

def main():
    # Get the test directory path from the ClientManager
    test_dir = os.path.join(os.path.expanduser("~"), "dlp_test")
    
    print("Starting DLP test sequence...")
    print(f"Monitoring directory: {test_dir}")
    
    # Test 1: Create multiple sensitive files
    print("\nTest 1: Creating multiple sensitive files...")
    files = []
    for i in range(3):
        content = f"This is a confidential document {i}\nContaining secret information"
        file_path = create_sensitive_file(test_dir, i, content)
        files.append(file_path)
        print(f"Created: {file_path}")
        time.sleep(2)  # Wait between operations
    
    # Test 2: Modify existing files
    print("\nTest 2: Modifying sensitive files...")
    for file_path in files[:2]:
        print(f"Modifying: {file_path}")
        modify_file(file_path)
        time.sleep(2)
    
    # Test 3: Move files
    print("\nTest 3: Moving sensitive files...")
    new_dir = Path(test_dir) / "subfolder"
    new_dir.mkdir(exist_ok=True)
    
    for file_path in files:
        new_path = new_dir / file_path.name
        print(f"Moving: {file_path} -> {new_path}")
        file_path.rename(new_path)
        time.sleep(2)
    
    print("\nDLP test sequence completed.")
    print("Check the server's alerts page to see if alerts were generated.")

if __name__ == "__main__":
    main()