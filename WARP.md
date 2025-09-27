# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a reverse engineering project for the TISC 2025 Level 9 CTF challenge "HWisntThatHardv2". The challenge involves analyzing an STM32-based IoT device firmware to find vulnerabilities and extract flags. The primary goal is to analyze a baremetal STM32 application that parses JSON commands and potentially exploit it to access protected memory slots.

## Architecture

### High-Level Structure
- **Target**: STM32F407 microcontroller firmware (`csit_iot.bin`)
- **Emulation**: Docker-containerized STM32 emulator with SPI flash storage
- **Communication**: JSON-based command interface over TCP (port 8000)
- **Memory Layout**: 
  - ROM at 0x08000000 (firmware)
  - RAM at 0x20000000 
  - CCM RAM at 0x10000000
  - External SPI flash with flag data

### Key Components
- **Command Parser**: Entry point at `FUN_08007260` - JSON command processor
- **Slot System**: Memory slots (0-15) containing data, with slot 0 holding the real flag
- **Data Validation**: Command structure validation and array comparison functions
- **SPI Flash Interface**: External storage containing flag and dummy data

## Common Development Commands

### Environment Setup
```bash
# Extract challenge files
tar -xf HWisntThatHard_v2.tar.xz

# Extract Ghidra decompiled code
unzip -q ghidra_decomp.zip
```

### Running the Challenge Locally
```bash
# Start the STM32 emulator (from dist/ directory)
cd dist/
docker-compose up

# Connect to local instance for testing
nc localhost 8000
```

### Static Analysis Commands
```bash
# Search for specific functions in decompiled code
grep -r "pattern" ghidra_decomp/*.c

# Count total decompiled functions
find ghidra_decomp -name "*.c" | wc -l

# Find JSON/command parsing functions
grep -l "JSON\|json\|slot\|data" ghidra_decomp/*.c
```

### Development Tools Installation
```bash
# Install pwntools for exploit development
pip install pwntools

# Install angr for binary analysis (supports STM32)
pip install angr

# Optional: Install Ghidra for additional analysis
# Use analyzeHeadless with -processor ARM:LE:32:Cortex for csit_iot.bin
```

## Key Functions and Memory Layout

### Critical Functions
- `FUN_08007260.c`: Main JSON command parser and entry point
- `FUN_0800023c.c`: Command processing and response handling  
- `FUN_08006d04.c`: Array/data parsing from JSON commands
- Functions handling "slot" parameter parsing and validation

### JSON Command Structure
The firmware accepts JSON commands with these known formats:
- `{"slot": X}` - View contents of slot X (0-15)
- `{"slot": X, "data": [array]}` - Compare slot X contents against provided array

### Memory Slots
- **Slot 0**: Contains the real flag `TISC{REAL_FLAG_GOES_HERE}`
- **Slots 1-15**: Contain dummy data/phrases
- **Target**: Exploit to access slot 0 contents

## Exploitation Strategy

### Static Analysis Focus
- Analyze `FUN_08007260.c` for JSON parsing vulnerabilities
- Look for buffer overflow opportunities in array processing functions
- Check bounds validation in slot access mechanisms
- Examine heap allocation patterns for potential overflow exploits

### Dynamic Analysis
- Test JSON command variations against local Docker instance
- Use pwntools to craft and test payloads
- Monitor for successful exploitation (return code 2 indicates failure)
- Connection closes on unsuccessful overflow attempts

### Known Constraints
- Live server has rotating dummy values in slots 1-15
- Heap exploitation suspected (off-by-one vulnerability)
- Scientific notation/exponentiation bypasses unlikely (this is pwn-focused)
- Connection terminates on failed exploitation attempts

## Testing and Validation

### Local Testing Workflow
1. Start Docker container: `docker-compose up`
2. Test basic commands: `echo '{"slot": 1}' | nc localhost 8000`  
3. Develop exploitation script with pwntools
4. Validate against local instance before attempting remote

### Remote Target
Production server available at: `nc chals.tisc25.ctf.sg 51728`
Only attempt remote exploitation after thorough local validation.

## Important Notes

- The challenge has **no time limit** - thorough static analysis is encouraged
- Focus on understanding the complete application structure before dynamic testing
- External SPI flash (`ext-flash.bin`) contains the actual flag data
- Emulator configuration in `config.yaml` defines memory regions and peripherals
- Challenge requires extracting flag from slot 0, not just finding it in static analysis

## Success Criteria

The challenge is solved when you can reliably extract the contents of slot 0 (the real flag) from the running firmware, either locally or from the remote server.

## Session scripts and how to run

These helper scripts were added during analysis:

- advanced_angr_analysis.py
  - Load the blob at 0x08000000 (ARMEL Thumb) and verify the 44-element boundary in the growth logic.
  - Run: /Users/saumil/codex/.venv/bin/python3 /Users/saumil/codex/advanced_angr_analysis.py

- sweep_44.py
  - Local and remote sweeps around N≈44 with slot-0 probes. Keep rate-limited on remote.
  - Run (local baseline + optional remote attempts): python3 /Users/saumil/codex/sweep_44.py

- remote_hunt.py
  - Remote-only formatter sweep (comma/colon/trailing spaces) around N∈{42..46} with jitter and backoff.
  - Run: python3 /Users/saumil/codex/remote_hunt.py

- angr_heap_driver.py
  - Angr driver that hooks UART, allocator, memset/memcpy and maps CCM/SRAM. Two modes: JSON handler (UART) and direct array parser harness.
  - Run: /Users/saumil/codex/.venv/bin/python3 /Users/saumil/codex/angr_heap_driver.py

Notes:
- For angr runs, ensure the venv (/Users/saumil/codex/.venv) is present with angr and pwntools installed.
- Local emulator: docker-compose up -d in dist/ then use nc localhost 8000 for manual probing.
