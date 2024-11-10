import multiprocessing
import time

def cpu_stress():
    while True:
        pass

if __name__ == "__main__":
    processes = []
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=cpu_stress)
        processes.append(p)
        p.start()

    time.sleep(30)
    for p in processes:
        p.terminate()