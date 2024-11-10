import os
import time
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def create_sensitive_file(test_dir: str, index: int, content: str):
    """Create a file with sensitive content."""
    file_path = Path(test_dir) / f"sensitive_file_{index}.txt"
    logging.info(f"Creating sensitive file: {file_path}")
    try:
        with open(file_path, "w") as f:
            f.write(content)
    except PermissionError:
        logging.error(f"Permission denied when trying to create {file_path}. Check your permissions.")
    return file_path

def modify_file(file_path: Path):
    """Modify an existing file."""
    logging.info(f"Modifying file: {file_path}")
    try:
        with open(file_path, "a") as f:
            f.write("\nAdditional confidential information")
    except PermissionError:
        logging.error(f"Permission denied when trying to modify {file_path}. Check your permissions.")

def main():
    # Get the test directory path in the user's home directory (macOS compatible)
    test_dir = os.path.join(os.path.expanduser("~"), "test_dlp")
    os.makedirs(test_dir, exist_ok=True)
    
    logging.info("Starting DLP test sequence...")
    logging.info(f"Monitoring directory: {test_dir}")
    
    # Test 1: Create multiple sensitive files
    logging.info("\nTest 1: Creating multiple sensitive files...")
    files = []
    sensitive_content = [
        "CONFIDENTIAL: This document contains secret information.",
        "PRIVATE: Internal use only - sensitive data enclosed.",
        "SECRET: Restricted access document with confidential details."
    ]
    
    for i, content in enumerate(sensitive_content):
        file_path = create_sensitive_file(test_dir, i, content)
        files.append(file_path)
        time.sleep(2)  # Wait between operations
    
    # Test 2: Modify existing files
    logging.info("\nTest 2: Modifying sensitive files...")
    for file_path in files[:2]:
        modify_file(file_path)
        time.sleep(2)
    
    logging.info("\nDLP test sequence completed.")
    logging.info("Check the logs for alert generation.")

if __name__ == "__main__":
    main()
