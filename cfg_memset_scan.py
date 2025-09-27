#!/usr/bin/env python3
import angr

BIN = "/Users/saumil/codex/dist/csit_iot.bin"
ROM_BASE = 0x08000000
MEMSET = 0x08026922

proj = angr.Project(BIN, auto_load_libs=False, main_opts={
    'backend':'blob', 'arch':'ARMEL', 'base_addr': ROM_BASE, 'entry_point': ROM_BASE,
})

print("Building CFG (this may take a while)...")
cfg = proj.analyses.CFGFast(data_references=True, normalize=True)

callers = set()
for func in cfg.kb.functions.values():
    for block in func.blocks:
        for insn in block.vex.statements:
            pass
    # use function.xrefs if available
    for callee in func.get_call_sites():
        # check if this call site calls MEMSET target (approximate)
        targets = func.get_call_target(callee)
        if isinstance(targets, int) and targets == MEMSET:
            callers.add(func.addr)
        elif isinstance(targets, set) and MEMSET in targets:
            callers.add(func.addr)

# Alternative: scan edges
for caller, callee in cfg.kb.functions.callgraph.edges():
    if callee == MEMSET:
        callers.add(caller)

print(f"Found {len(callers)} functions calling memset at {hex(MEMSET)}:")
for a in sorted(callers):
    print(hex(a))
