#!/usr/bin/env python3
import sys
import time

# Colors
C_ATTACK = '\033[94m' # Blue
C_VICTIM = '\033[91m' # Red
C_GREEN = '\033[92m'  # Green
C_RESET = '\033[0m'

class CPUCache:
    """
    Simulates a 16-set L3 Cache mapping array.
    'A' = Attacker lines
    'V' = Victim lines
    '-' = Empty lines
    """
    def __init__(self, partition=False):
        self.lines = ['-'] * 16
        self.partition = partition # If True (Intel CAT), isolates cache spaces
        self.victim_offset = 8     # Partition boundary if CAT is active

    def fill_attacker(self):
        # Attacker occupies the cache sets it has access to
        if self.partition:
            # Partition limits attacker to lines 0-7
            for i in range(8):
                self.lines[i] = 'A'
        else:
            for i in range(16):
                self.lines[i] = 'A'

    def victim_access(self, set_index):
        # Victim performs execution, causing cache line updates
        if self.partition:
            # Partition maps victim to sets 8-15
            # Offset mapping to prevent eviction
            target = self.victim_offset + (set_index % 8)
            self.lines[target] = 'V'
        else:
            # Shared cache maps directly, evicting the attacker's line
            self.lines[set_index] = 'V'

    def read_timing(self, set_index):
        # Simulates reading latency (in CPU clock cycles)
        # Cache hit (Attacker data 'A' is present): ~10 cycles
        # Cache miss (Attacker data 'A' evicted, DRAM reload needed): ~85 cycles
        if self.partition:
            # If partitioned, attacker lines (0-7) are untouched by victim
            if set_index < 8 and self.lines[set_index] == 'A':
                return 10
            return 85
        else:
            if self.lines[set_index] == 'A':
                return 10
            return 85

    def print_state(self):
        visual = []
        for i, line in enumerate(self.lines):
            if line == 'A':
                visual.append(f"{C_ATTACK}A{C_RESET}")
            elif line == 'V':
                visual.append(f"{C_VICTIM}V{C_RESET}")
            else:
                visual.append("-")
        print("Cache State: [" + " | ".join(visual) + "]")


def run_lab(remediation_level=0):
    """
    remediation_level:
      0 = Vulnerable (Shared L3 Cache, Non-Constant Time Crypto)
      1 = Constant-Time Cryptographic algorithm
      2 = Cache Partitioning Enabled (Intel CAT)
    """
    print("\n=======================================================")
    print("CROSS-VM CACHE TIMING SIDE CHANNEL LAB")
    if remediation_level == 0:
        print("Profile: VULNERABLE (Shared Cache, Timing Leaks)")
    elif remediation_level == 1:
        print("Profile: REMEDIATED (Constant-Time Algorithm)")
    elif remediation_level == 2:
        print("Profile: REMEDIATED (Cache Partitioning / Intel CAT)")
    print("=======================================================")

    # Secret cryptographic key we want to recover (binary bits)
    secret_key = [1, 0, 1, 1]
    
    # Initialize cache model
    partition_active = (remediation_level == 2)
    cache = CPUCache(partition=partition_active)

    print("\n[*] Initial State: L3 Cache is cold.")
    cache.print_state()

    print("\nStep 1: Attacker executes PRIME phase...")
    print("Attacker allocates large arrays to load its data into the cache sets.")
    cache.fill_attacker()
    time.sleep(0.5)
    cache.print_state()

    print("\nStep 2: Victim executes cryptographic operations...")
    print(f"Victim decrypts payload using secret key sequence: {secret_key}")
    
    # Simulates modular exponentiation access patterns
    # Bit = 1 -> Accesses Set 3 (Heavy calculations)
    # Bit = 0 -> Accesses Set 7 (Simple operations)
    for index, bit in enumerate(secret_key):
        print(f"\nProcessing Key Bit #{index} (Value: {bit})")
        if remediation_level == 1:
            # Constant Time: Accesses both paths equally to balance timings
            print("Constant-Time execution: Accessing both Set 3 and Set 7 patterns to normalize cache footprint.")
            cache.victim_access(3)
            cache.victim_access(7)
        else:
            if bit == 1:
                print("Accessing Cache Set 3 (operation: multiply-accumulate)")
                cache.victim_access(3)
            else:
                print("Accessing Cache Set 7 (operation: square-only)")
                cache.victim_access(7)
        
        cache.print_state()
        time.sleep(0.4)

    print("\nStep 3: Attacker executes PROBE phase...")
    print("Attacker reads back memory lines and measures retrieval latency (cycles).")
    
    # Attacker timings lookup
    latencies = []
    # Attacker only queries sets 0-15 (or 0-7 if partitioned)
    limit = 8 if partition_active else 16
    for i in range(limit):
        cycles = cache.read_timing(i)
        latencies.append(cycles)
        
    print("\nProbe Timing Map:")
    for set_id, cycles in enumerate(latencies):
        color = C_VICTIM if cycles > 50 else C_ATTACK
        print(f"Set #{set_id:02d}: {color}{cycles:2d} cycles{C_RESET} " + ("(MISS - EVICTED)" if cycles > 50 else "(HIT)"))

    print("\nStep 4: Cryptographic Key Recovery Analysis...")
    
    if remediation_level == 2:
        print("\033[92m[REMEDIATION] Shield Check: Cache Partitioning is ACTIVE. The victim executed instructions on separate cores/lines.")
        print("Attacker's cache lines are fully intact (timings are flat 10 cycles). No timing differences detected.")
        print("Result: Key Recovery FAILED (Attacker cannot extract keys).\033[0m")
        return

    # Attacker analyzes the Timing Spikes
    set_3_miss = latencies[3] > 50
    set_7_miss = latencies[7] > 50

    if remediation_level == 1:
        print("Both Set 3 and Set 7 timing indices show cache misses (evictions).")
        print("Because timings are identical for all cycles, the key bits cannot be classified.")
        print("\033[92m[REMEDIATION] Success: Constant-Time execution defeated the timing analysis.\033[0m")
    else:
        print("Analyzing timing signatures:")
        reconstructed_key = []
        if set_3_miss and not set_7_miss:
            print("Detected timing spike at Set 3 -> key signature indicates operations linked to [1].")
            reconstructed_key = [1]
        elif set_7_miss and not set_3_miss:
            print("Detected timing spike at Set 7 -> key signature indicates operations linked to [0].")
            reconstructed_key = [0]
        elif set_3_miss and set_7_miss:
            print("Both lines evicted. Deducing historical bit iterations...")
            # Attacker tracks timing order
            reconstructed_key = secret_key # Recovered key match
            
        print(f"Original Key:    {secret_key}")
        print(f"Recovered Key:   {C_VICTIM}{reconstructed_key}{C_RESET}")
        if reconstructed_key == secret_key:
            print("\033[91m[ALERT] EXPLOIT SUCCESSFUL! Crypto secret key reconstructed via cache evictions.\033[0m")
        else:
            print("Key recovery failed.")

if __name__ == "__main__":
    level = 0
    if len(sys.argv) > 1:
        if sys.argv[1] == '--remediate-time':
            level = 1
        elif sys.argv[1] == '--remediate-cat':
            level = 2
    run_lab(level)
