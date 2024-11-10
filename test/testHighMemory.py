import psutil
import os
import time

if __name__ == "__main__":
    large_list = []
    process = psutil.Process(os.getpid())  # Get current process
    try:
        while True:
            large_list.append([0] * 10**6)
            print(f"Memory usage: {process.memory_info().rss / (1024 * 1024)} MB")  # Print memory usage in MB
            time.sleep(1)
    except MemoryError:
        print("Memory usage reached limit!")