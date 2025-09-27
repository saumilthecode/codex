#!/usr/bin/env python3
# Angr driver to run STM32 blob and feed specific JSON lines via hooked UART.
# Maps SRAM per dist/config.yaml, hooks allocator and device I/O.

import angr
import claripy

import struct

ROM_BASE   = 0x08000000
JSON_MAIN  = 0x08007260  # Thumb
ARR_PARSER = 0x08006d04  # Thumb
ALLOC_FN   = 0x08008466  # Thumb  (xmalloc-style wrapper)
MALLOC_FN  = 0x080249b4  # real allocator
FREE_FN    = 0x080249c4  # real free
UART_FN    = 0x08004974  # Thumb

# Peripheral/logging we stub (best-effort, more can be added if needed)
STUBS = [
    0x080017dc, 0x080025bc, 0x08002bec, 0x08004328, 0x08001fa8,
    0x080024b0, 0x080176b6, 0x08017740, 0x080178c4, 0x080104f6, 0x08010502,
    0x08000664, 0x0800061c, 0x080006b0, 0x080011c0,
]

MEMSET_FN  = 0x08026922
MEMCPY_FN  = 0x08028666

# SRAM map from dist/config.yaml
CCM_BASE = 0x10000000
CCM_SIZE = 0x00018000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000

# Heap region inside SRAM
HEAP_BASE = SRAM_BASE + 0x4000
HEAP_SIZE = 0x00010000

# Minimal allocator model constants
HDR_SIZE   = 8  # 4-byte size + 4-byte next pointer (for free-list)
ALIGN      = 8  # align chunks
MIN_SPLIT  = HDR_SIZE + 8

# Input payloads (3 lines), as user-specified
def jline(obj):
    import json
    return (json.dumps(obj) + "\n").encode()

LINES = [
    jline({"slot": 1, "data": [69,2,0]}),
    jline({"slot": 1, "data": ([0]*44) + [65,11,0]}),
    jline({"slot": 1, "data": ([0]*44) + [75,37,0]}),
]

class InputFeed:
    def __init__(self, lines):
        blob = b"".join(lines)
        self.buf = bytearray(blob)
        self.idx = 0
    def read(self, n):
        out = []
        for _ in range(n):
            if self.idx >= len(self.buf):
                out.append(10)  # newline if exhausted
            else:
                out.append(self.buf[self.idx])
                self.idx += 1
        return bytes(out)

class UARTRead(angr.SimProcedure):
    # int FUN_08004974(dev, dst, len, timeout)
    def run(self, dev, dst, length, timeout):
        st = self.state
        n = st.solver.eval(length)
        data = st.globals['uart_feed'].read(n)
        st.memory.store(dst, data)
        # Return 0 (OK)
        return claripy.BVV(0, 32)

class NopRet0(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return self.state.solver.BVV(0, 32)

class NopVoid(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return

# ---- Realistic heap model ----

def _align_up(x, a=ALIGN):
    r = x % a
    return x if r == 0 else x + (a - r)

class HeapModel:
    def __init__(self, st, base, size):
        self.st = st
        self.base = base
        self.end  = base + size
        # One initial free chunk spanning the region
        self.freelist = [(base, size)]  # list of (addr, size)
        self.used = {}                  # addr -> {'size': total_chunk_size, 'usable': usable_size}

    def dump(self):
        print("HEAP DUMP: used=%d free=%d" % (len(self.used), len(self.freelist)))
        for a,rec in sorted(self.used.items()):
            print("  USED  0x%08x size=%4d usable=%4d" % (a, rec['size'], rec['usable']))
        for a,s in self.freelist:
            print("  FREE  0x%08x size=%4d" % (a, s))

    def _insert_free(self, addr, size):
        # insert and coalesce neighbors
        self.freelist.append((addr, size))
        self.freelist.sort(key=lambda t: t[0])
        merged = []
        for a,s in self.freelist:
            if not merged:
                merged.append((a,s))
            else:
                pa, ps = merged[-1]
                if pa + ps == a:  # contiguous
                    merged[-1] = (pa, ps + s)
                else:
                    merged.append((a,s))
        self.freelist = merged

    def malloc(self, req_size):
        st = self.st
        if req_size <= 0:
            req_size = 1
        usable = _align_up(req_size, ALIGN)
        need = usable + HDR_SIZE
        # first-fit
        for i, (fa, fs) in enumerate(self.freelist):
            if fs >= need:
                alloc_addr = fa
                rem = fs - need
                # write header: size and next (unused in our model)
                st.memory.store(alloc_addr + 0, (need).to_bytes(4, 'little'))
                st.memory.store(alloc_addr + 4, (0).to_bytes(4, 'little'))
                # update free list
                del self.freelist[i]
                if rem >= MIN_SPLIT:
                    self.freelist.insert(i, (alloc_addr + need, rem))
                self.used[alloc_addr] = {'size': need, 'usable': usable}
                return alloc_addr + HDR_SIZE
        # out of memory, return a dummy but non-null pointer inside RAM
        return SRAM_BASE + 0x100

    def free(self, user_ptr):
        if user_ptr is None:
            return
        hdr = user_ptr - HDR_SIZE
        rec = self.used.pop(hdr, None)
        if rec is None:
            # double-free or unknown block; ignore
            return
        self._insert_free(hdr, rec['size'])

    def chunk_for_addr(self, addr):
        # return (hdr_addr, record) for the chunk that contains addr in its user area
        for hdr, rec in self.used.items():
            user_start = hdr + HDR_SIZE
            user_end   = user_start + rec['usable']
            if user_start <= addr < user_end:
                return hdr, rec
        return None, None

    def user_end_for_hdr(self, hdr, rec):
        return hdr + HDR_SIZE + rec['usable']

class XMallocBump(angr.SimProcedure):
    # Compatibility wrapper: use HeapModel as backing store
    def run(self, size):
        st = self.state
        hm = st.globals.get('heap_model')
        if hm is None:
            # initialize HeapModel lazily
            hm = HeapModel(st, st.globals['heap_base'], st.globals['heap_size'])
            st.globals['heap_model'] = hm
        req = st.solver.eval(size)
        ptr = hm.malloc(req)
        return claripy.BVV(ptr, 32)

class MallocProc(angr.SimProcedure):
    # real allocator
    def run(self, size):
        st = self.state
        hm = st.globals.get('heap_model')
        if hm is None:
            hm = HeapModel(st, st.globals['heap_base'], st.globals['heap_size'])
            st.globals['heap_model'] = hm
        req = st.solver.eval(size)
        ptr = hm.malloc(req)
        return claripy.BVV(ptr, 32)

class FreeProc(angr.SimProcedure):
    # real free
    def run(self, user_ptr):
        st = self.state
        hm = st.globals.get('heap_model')
        if hm is None:
            hm = HeapModel(st, st.globals['heap_base'], st.globals['heap_size'])
            st.globals['heap_model'] = hm
        uptr = st.solver.eval(user_ptr)
        hm.free(uptr)
        return claripy.BVV(0, 32)

class MemsetProc(angr.SimProcedure):
    # void *memset(void *s, int c, size_t n)
    def run(self, dst, val, n):
        st = self.state
        dst_v = st.solver.eval(dst)
        n_v = st.solver.eval(n)
        c_v = st.solver.eval(val) & 0xff
        # Detect and log 16-byte zero padding and whether it crosses a chunk boundary
        if c_v == 0 and n_v >= 16:
            pads = st.globals.get('pads')
            if pads is None:
                pads = []
                st.globals['pads'] = pads
            pads.append((st.addr, dst_v, n_v))
            # OOB check against heap chunks
            hm = st.globals.get('heap_model')
            if hm is not None:
                hdr, rec = hm.chunk_for_addr(dst_v)
                if rec is not None:
                    user_end = hm.user_end_for_hdr(hdr, rec)
                    if dst_v + n_v > user_end:
                        oobs = st.globals.get('oob_pads')
                        if oobs is None:
                            oobs = []
                            st.globals['oob_pads'] = oobs
                        oobs.append({
                            'pc': st.addr,
                            'dst': dst_v,
                            'len': n_v,
                            'user_end': user_end,
                            'hdr': hdr,
                        })
        st.memory.store(dst_v, bytes([c_v]) * n_v)
        return claripy.BVV(dst_v, 32)

class MemcpyProc(angr.SimProcedure):
    # void *memcpy(void *dest, const void *src, size_t n)
    def run(self, dst, src, n):
        st = self.state
        dst_v = st.solver.eval(dst)
        src_v = st.solver.eval(src)
        n_v = st.solver.eval(n)
        try:
            data = st.memory.load(src_v, n_v, fallback=claripy.BVV(0, n_v*8))
        except Exception:
            data = claripy.BVV(0, n_v*8)
        st.memory.store(dst_v, data)
        return claripy.BVV(dst_v, 32)

class BuggyPadShim(angr.SimProcedure):
    # void shim(uint32_t* param2_vec)
    # param2_vec layout: [base, cur, end]
    def run(self, param2_ptr):
        st = self.state
        p = st.solver.eval(param2_ptr)
        base = st.solver.eval(st.memory.load(p + 0, 4, endness='Iend_LE'))
        cur  = st.solver.eval(st.memory.load(p + 4, 4, endness='Iend_LE'))
        end  = st.solver.eval(st.memory.load(p + 8, 4, endness='Iend_LE'))
        used = cur - base
        cap  = end - base
        # Perform the buggy sequence: write 16 zeros at base+used, then used+=4
        dst = base + used
        st.memory.store(dst, b"\x00" * 16)
        used2 = used + 4
        st.memory.store(p + 4, (base + used2).to_bytes(4, 'little'))
        # Log pad and OOB relative to heap chunk bound if possible
        pads = st.globals.get('pads')
        if pads is None:
            pads = []
            st.globals['pads'] = pads
        pads.append((st.addr, dst, 16))
        hm = st.globals.get('heap_model')
        if hm is not None:
            hdr, rec = hm.chunk_for_addr(dst)
            if rec is not None:
                user_end = hm.user_end_for_hdr(hdr, rec)
                if dst + 16 > user_end:
                    oobs = st.globals.get('oob_pads')
                    if oobs is None:
                        oobs = []
                        st.globals['oob_pads'] = oobs
                    oobs.append({
                        'pc': st.addr,
                        'dst': dst,
                        'len': 16,
                        'user_end': user_end,
                        'hdr': hdr,
                        'cap': cap,
                        'used': used,
                        'delta': cap - used,
                    })
        return claripy.BVV(0, 32)


def make_project():
    bin_path = "/Users/saumil/codex/dist/csit_iot.bin"
    proj = angr.Project(
        bin_path,
        auto_load_libs=False,
        main_opts={
            'backend': 'blob',
            'arch': 'ARMEL',
            'base_addr': ROM_BASE,
            'entry_point': ROM_BASE,
        },
    )
    # Hooks
    proj.hook(UART_FN, UARTRead())
    # Hook both the wrapper and the real allocator to our heap model
    proj.hook(ALLOC_FN, XMallocBump())
    proj.hook(MALLOC_FN, MallocProc())
    proj.hook(FREE_FN,   FreeProc())
    proj.hook(MEMSET_FN, MemsetProc())
    proj.hook(MEMCPY_FN, MemcpyProc())
    for a in STUBS:
        # logging/IO functions may expect void or int; we choose void stubs for most
        proj.hook(a, NopVoid())
    return proj


def make_state_for_line(proj, line_bytes: bytes, slack: int = 12):
    # Ensure newline-terminated
    if not line_bytes.endswith(b"\n"):
        line_bytes = line_bytes + b"\n"
    # Create a call_state to JSON_MAIN with param1/param2 pointers set
    st = proj.factory.call_state(JSON_MAIN | 1, SRAM_BASE + 0x200, SRAM_BASE + 0x300)
    # Map SRAM and CCM explicitly (ignore if already mapped)
    for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
        try:
            st.memory.map_region(base, size, 7)
        except Exception:
            pass

    # Initialize our heap model state
    st.globals['heap_base'] = HEAP_BASE
    st.globals['heap_size'] = HEAP_SIZE
    st.globals['heap_model'] = HeapModel(st, HEAP_BASE, HEAP_SIZE)

    # Param blocks
    param1 = SRAM_BASE + 0x200
    param2 = SRAM_BASE + 0x300
    st.memory.store(param1, b"\x00" * 0x40)
    st.memory.store(param2, b"\x00" * 0x40)

    # Install UART feed for the driver loop
    st.globals['uart_feed'] = InputFeed([line_bytes])

    # Prepare a {base,cur,end} vector for any paths that read it
    base = SRAM_BASE + 0x1000
    used = 0
    cap = len(line_bytes) + max(1, slack)
    st.memory.store(base, b"\x00" * (cap + 1))
    st.memory.store(param2 + 0, base.to_bytes(4, 'little'))
    st.memory.store(param2 + 4, (base + used).to_bytes(4, 'little'))
    st.memory.store(param2 + 8, (base + cap).to_bytes(4, 'little'))

    # Inspect memory writes to find suspicious zeroing blocks
    def on_write(state):
        try:
            data = state.inspect.mem_write_expr
            addr = state.inspect.mem_write_address
            size = state.inspect.mem_write_length
            if state.solver.symbolic(addr) or state.solver.symbolic(size):
                return
            a = state.solver.eval(addr)
            n = state.solver.eval(size)
            # track zero stores up to 16 bytes
            if 1 <= n <= 16:
                try:
                    val = state.solver.eval(data)
                    if val == 0:
                        z = state.globals.get('zero_writes')
                        if z is None:
                            z = []
                            state.globals['zero_writes'] = z
                        z.append((state.addr, a, n))
                except Exception:
                    pass
        except Exception:
            pass

    st.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)

    # reduce unconstrained noise: zero-fill
    import angr as _angr
    st.options.add(_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    st.options.add(_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    return st


def to_array_bytes(ints):
    s = "[" + ",".join(str(x) for x in ints) + "]"
    return s.encode()


def run_line(proj, line_bytes: bytes, slack_values=(8, 10, 12, 14)):
    for slack in slack_values:
        st = make_state_for_line(proj, line_bytes, slack=slack)
        simgr = proj.factory.simulation_manager(st)
        # step a bit; since we start in the JSON handler, it should return reasonably fast
        for _ in range(50000):
            if len(simgr.active) == 0:
                break
            simgr.step()
        zs = st.globals.get('zero_writes', [])
        pads = st.globals.get('pads', [])
        oobs = st.globals.get('oob_pads', [])
        print(f"slack={slack} zero_writes={len(zs)} pads={len(pads)} oob_pads={len(oobs)}")
        for tup in pads[:5]:
            pc, addr, ln = tup
            print("  PAD PC=0x%08x -> [0x%08x] len=%d" % (pc, addr, ln))
        for ev in oobs[:5]:
            print("  OOB PAD pc=0x%08x dst=0x%08x len=%d user_end=0x%08x hdr=0x%08x" % (ev['pc'], ev['dst'], ev['len'], ev['user_end'], ev['hdr']))


def run_pad_direct_sweep(proj):
    print("=== Direct pad sweep (offline calc over heap model) ===")
    for cap in (64, 128):
        for delta in range(4, 16):
            st = proj.factory.blank_state()
            # Map memory for setup state
            for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
                try:
                    st.memory.map_region(base, size, 7)
                except Exception:
                    pass
            # initialize heap model
            st.globals['heap_base'] = HEAP_BASE
            st.globals['heap_size'] = HEAP_SIZE
            hm = HeapModel(st, HEAP_BASE, HEAP_SIZE)
            st.globals['heap_model'] = hm
            # allocate line buffer chunk A and victim chunk B
            a_ptr = hm.malloc(cap)
            _b_ptr = hm.malloc(32)
            # compute the buggy pad effects
            base = a_ptr
            used = cap - delta
            end  = a_ptr + cap
            dst  = base + used
            # compute OOB
            user_end = end
            if dst + 16 > user_end:
                print(f"cap={cap} delta={delta} -> OOB: dst=0x{dst:08x} user_end=0x{user_end:08x}")
                return True
            else:
                print(f"cap={cap} delta={delta} -> pad yes, OOB no")
    print("No OOB in direct sweep (unexpected)")
    return False

def _build_line2(base_val=0, tail=(65,11,0), comma_space=0, trail_spaces=0):
    # Manual builder to control spaces
    vals = [int(base_val)] * 44 + list(tail)
    sep = ',' + (' ' * comma_space)
    body = '[' + sep.join(str(x) for x in vals) + ']'
    s = '{"slot": 1, "data": ' + body + '}' + (' ' * trail_spaces)
    return s.encode() + b"\n"

def run_two_line_instrumented(proj, base_val=0, tail=(65,11,0), comma_space=0, trail_spaces=0):
    import json as _json
    # Build two lines as one UART feed
    line1 = (_json.dumps({"slot":1, "data":[69,2,0]}) + "\n").encode()
    line2 = _build_line2(base_val, tail, comma_space, trail_spaces)
    # Create initial state at JSON handler
    st = proj.factory.call_state(JSON_MAIN | 1, SRAM_BASE + 0x200, SRAM_BASE + 0x300)
    # Map memory
    for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
        try:
            st.memory.map_region(base, size, 7)
        except Exception:
            pass
    # Heap model
    st.globals['heap_base'] = HEAP_BASE
    st.globals['heap_size'] = HEAP_SIZE
    hm = HeapModel(st, HEAP_BASE, HEAP_SIZE)
    st.globals['heap_model'] = hm
    
    # Pre-allocate line buffer chunk and victim chunk for adjacency
    line_cap = 256  # Target capacity for line buffer
    line_ptr = hm.malloc(line_cap)
    victim_ptr = hm.malloc(64)  # Victim chunk right after line buffer
    
    # Params
    param1 = SRAM_BASE + 0x200
    param2 = SRAM_BASE + 0x300
    st.memory.store(param1, b"\x00" * 0x40)
    st.memory.store(param2, b"\x00" * 0x40)
    
    # Set param2 vector to point to our pre-allocated line buffer
    # We want cap - used in [4..15] range for OOB
    used = line_cap - 8  # Leave 8 bytes slack (in OOB range)
    st.memory.store(param2 + 0, (line_ptr).to_bytes(4, 'little'))
    st.memory.store(param2 + 4, (line_ptr + used).to_bytes(4, 'little'))
    st.memory.store(param2 + 8, (line_ptr + line_cap).to_bytes(4, 'little'))
    
    # Set victim_start to victim chunk user area for read tracing
    st.globals['victim_start'] = victim_ptr
    
    # UART feed for two lines
    st.globals['uart_feed'] = InputFeed([line1, line2])
    # Instrument and run
    _install_pad_read_tracers(st)
    _run_and_summarize(proj, st)

def _install_pad_read_tracers(st):
    # Instrumentation storage
    st.globals['zero_writes_list'] = []  # (pc, addr, len)
    st.globals['pad_block'] = None       # {'start':addr, 'len':n}
    st.globals['victim_start'] = None
    st.globals['reads_near_victim'] = [] # (pc, lr, addr, n, off)

    # Zero-write aggregation
    def on_write(state):
        try:
            addr_bv = state.inspect.mem_write_address
            size_bv = state.inspect.mem_write_length
            data_bv = state.inspect.mem_write_expr
            if state.solver.symbolic(addr_bv) or state.solver.symbolic(size_bv) or data_bv is None:
                return
            a = state.solver.eval(addr_bv)
            n = state.solver.eval(size_bv)
            if n <= 0 or n > 32:
                return
            try:
                val = state.solver.eval(data_bv)
            except Exception:
                return
            if val == 0:
                zl = state.globals['zero_writes_list']
                zl.append((int(state.addr), a, n))
        except Exception:
            pass

    # Read tracer near victim (header + user area)
    def on_read(state):
        try:
            vs = state.globals.get('victim_start')
            if vs is None:
                return
            addr_bv = state.inspect.mem_read_address
            size_bv = state.inspect.mem_read_length
            if state.solver.symbolic(addr_bv) or state.solver.symbolic(size_bv):
                return
            a = state.solver.eval(addr_bv)
            n = state.solver.eval(size_bv)
            
            # Check reads in victim header area (8 bytes before user area)
            victim_hdr = vs - HDR_SIZE
            if a + n > victim_hdr and a < vs + 0x60:
                off = a - vs
                lr = 0
                try:
                    lr = state.solver.eval(state.regs.lr)
                except Exception:
                    pass
                # Mark if it's a header read
                is_header = a < vs
                state.globals['reads_near_victim'].append((int(state.addr), lr, a, n, off, is_header))
        except Exception:
            pass

    st.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)
    st.inspect.b('mem_read', when=angr.BP_BEFORE, action=on_read)

    # reduce noise
    import angr as _angr
    st.options.add(_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    st.options.add(_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)


def _run_and_summarize(proj, st):
    simgr = proj.factory.simulation_manager(st)
    for _ in range(120000):
        if not simgr.active:
            break
        simgr.step()
    # After run: merge zero writes to find 16-byte contiguous blocks
    zw = st.globals['zero_writes_list']
    zw.sort(key=lambda x: x[1])  # by address
    merged = []
    for pc,a,n in zw:
        if not merged:
            merged.append([a, a+n])
        else:
            la, lb = merged[-1]
            if a <= lb and n > 0:
                merged[-1][1] = max(lb, a+n)
            else:
                merged.append([a, a+n])
    pad_block = None
    for a,b in merged:
        if b - a >= 16:
            pad_block = {'start': a, 'len': b - a}
            break
    st.globals['pad_block'] = pad_block

    # Determine victim_start from heap model if pad found
    if pad_block is not None:
        hm = st.globals['heap_model']
        hdr, rec = hm.chunk_for_addr(pad_block['start'])
        if rec is not None:
            line_user_start = hdr + HDR_SIZE
            user_end = line_user_start + rec['usable']
            st.globals['victim_start'] = user_end
        else:
            st.globals['victim_start'] = pad_block['start'] + 16

    # Print summary
    print('pad_block:', st.globals['pad_block'])
    print('victim_start:', hex(st.globals['victim_start']) if st.globals['victim_start'] else None)
    reads = st.globals['reads_near_victim']
    for r in reads[:8]:
        if len(r) == 6:
            pc, lr, a, n, off, is_header = r
            hdr_str = "HEADER" if is_header else "USER"
            print('READ pc=0x%08x lr=0x%08x addr=0x%08x len=%d off=%d %s' % (pc, lr, a, n, off, hdr_str))
        else:
            pc, lr, a, n, off = r
            print('READ pc=0x%08x lr=0x%08x addr=0x%08x len=%d off=%d' % (pc, lr, a, n, off))


def run_parse_entry_instrumented(proj, cap=256, delta=8):
    # Create a call_state directly into FUN_08007260 with heap-backed {base,cur,end}
    st = proj.factory.call_state(JSON_MAIN | 1, SRAM_BASE + 0x220, SRAM_BASE + 0x320)
    for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
        try:
            st.memory.map_region(base, size, 7)
        except Exception:
            pass
    st.globals['heap_base'] = HEAP_BASE
    st.globals['heap_size'] = HEAP_SIZE
    st.globals['heap_model'] = HeapModel(st, HEAP_BASE, HEAP_SIZE)
    param1 = SRAM_BASE + 0x220
    param2 = SRAM_BASE + 0x320
    st.memory.store(param1, b"\x00" * 0x40)
    st.memory.store(param2, b"\x00" * 0x40)
    # Allocate heap-backed buffer and set used so cap - used = delta
    hm = st.globals['heap_model']
    vptr = hm.malloc(cap)
    used = cap - delta
    st.memory.store(param2 + 0, (vptr).to_bytes(4, 'little'))
    st.memory.store(param2 + 4, (vptr + used).to_bytes(4, 'little'))
    st.memory.store(param2 + 8, (vptr + cap).to_bytes(4, 'little'))
    _install_pad_read_tracers(st)
    _run_and_summarize(proj, st)

def run_combined_harness(proj, cap=256, delta=8):
    """Combined harness: heap-backed pad + immediate consumer invocation"""
    # Create state at JSON handler with heap-backed buffer
    st = proj.factory.call_state(JSON_MAIN | 1, SRAM_BASE + 0x220, SRAM_BASE + 0x320)
    for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
        try:
            st.memory.map_region(base, size, 7)
        except Exception:
            pass
    st.globals['heap_base'] = HEAP_BASE
    st.globals['heap_size'] = HEAP_SIZE
    hm = HeapModel(st, HEAP_BASE, HEAP_SIZE)
    st.globals['heap_model'] = hm
    
    # Pre-allocate line buffer and victim chunk
    line_ptr = hm.malloc(cap)
    victim_ptr = hm.malloc(64)
    
    # Set up param2 vector for OOB condition
    used = cap - delta
    param1 = SRAM_BASE + 0x220
    param2 = SRAM_BASE + 0x320
    st.memory.store(param1, b"\x00" * 0x40)
    st.memory.store(param2, b"\x00" * 0x40)
    st.memory.store(param2 + 0, (line_ptr).to_bytes(4, 'little'))
    st.memory.store(param2 + 4, (line_ptr + used).to_bytes(4, 'little'))
    st.memory.store(param2 + 8, (line_ptr + cap).to_bytes(4, 'little'))
    
    # Set victim_start for read tracing
    st.globals['victim_start'] = victim_ptr
    
    # Install tracers
    _install_pad_read_tracers(st)
    
    # Run the pad phase
    print(f"=== Combined harness: cap={cap}, delta={delta} ===")
    simgr = proj.factory.simulation_manager(st)
    for _ in range(50000):  # Run pad phase
        if not simgr.active:
            break
        simgr.step()
    
    # After pad, immediately invoke array parser to trigger consumer reads
    if simgr.active:
        print("Invoking array parser consumer...")
        # Create array parser call state
        arr_st = proj.factory.call_state(ARR_PARSER | 1, SRAM_BASE + 0x400, SRAM_BASE + 0x800, SRAM_BASE + 0x900, SRAM_BASE + 0x904)
        for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
            try:
                arr_st.memory.map_region(base, size, 7)
            except Exception:
                pass
        
        # Copy heap model and victim_start from pad state
        arr_st.globals['heap_base'] = HEAP_BASE
        arr_st.globals['heap_size'] = HEAP_SIZE
        arr_st.globals['heap_model'] = hm
        arr_st.globals['victim_start'] = victim_ptr
        
        # Set up array parser parameters
        vec = SRAM_BASE + 0x400
        status = SRAM_BASE + 0x800
        pcur_ptr = SRAM_BASE + 0x900
        pend_ptr = SRAM_BASE + 0x904
        
        arr_st.memory.store(vec, b"\x00"*0x10)
        arr_st.memory.store(status, (0).to_bytes(4,'little'))
        
        # Set up input array
        test_ints = [69, 2, 0]
        arr_bytes = to_array_bytes(test_ints)
        in_base = SRAM_BASE + 0x2000
        arr_st.memory.store(in_base, arr_bytes)
        arr_st.memory.store(pcur_ptr, in_base.to_bytes(4,'little'))
        arr_st.memory.store(pend_ptr, (in_base + len(arr_bytes)).to_bytes(4,'little'))
        
        # Install read tracers
        _install_pad_read_tracers(arr_st)
        
        # Run array parser
        arr_simgr = proj.factory.simulation_manager(arr_st)
        for _ in range(20000):
            if not arr_simgr.active:
                break
            arr_simgr.step()
        
        # Summarize results
        _run_and_summarize(proj, arr_st)
    else:
        print("No active states after pad phase")
        _run_and_summarize(proj, st)


def run_array_parser(proj, ints):
    # Prepare parameters for FUN_08006d04(uint* vec, int* status, char** pcur, char** pend)
    st = proj.factory.call_state(ARR_PARSER | 1, SRAM_BASE + 0x400, SRAM_BASE + 0x800, SRAM_BASE + 0x900, SRAM_BASE + 0x904)
    # Map regions
    for base, size in [(CCM_BASE, CCM_SIZE), (SRAM_BASE, SRAM_SIZE), (HEAP_BASE, HEAP_SIZE)]:
        try:
            st.memory.map_region(base, size, 7)
        except Exception:
            pass

    # Initialize heap model for this state
    st.globals['heap_base'] = HEAP_BASE
    st.globals['heap_size'] = HEAP_SIZE
    st.globals['heap_model'] = HeapModel(st, HEAP_BASE, HEAP_SIZE)

    vec = SRAM_BASE + 0x400
    status = SRAM_BASE + 0x800
    pcur_ptr = SRAM_BASE + 0x900
    pend_ptr = SRAM_BASE + 0x904

    # zero-initialize vec/status
    st.memory.store(vec, b"\x00"*0x10)
    st.memory.store(status, (0).to_bytes(4,'little'))

    # initial small capacity for vec {base, cur, end}
    out_base = SRAM_BASE + 0x1200
    out_cap = 8
    st.memory.store(out_base, b"\x00"*(out_cap))
    st.memory.store(vec + 0, out_base.to_bytes(4,'little'))
    st.memory.store(vec + 4, out_base.to_bytes(4,'little'))
    st.memory.store(vec + 8, (out_base+out_cap).to_bytes(4,'little'))

    # input array bytes
    arr_bytes = to_array_bytes(ints)
    in_base = SRAM_BASE + 0x2000
    st.memory.store(in_base, arr_bytes)
    st.memory.store(pcur_ptr, in_base.to_bytes(4,'little'))
    st.memory.store(pend_ptr, (in_base + len(arr_bytes)).to_bytes(4,'little'))

    # instrument OOB writes relative to vec end
    def on_write(state):
        try:
            addr = state.inspect.mem_write_address
            size = state.inspect.mem_write_length
            if state.solver.symbolic(addr) or state.solver.symbolic(size):
                return
            a = state.solver.eval(addr)
            n = state.solver.eval(size)
            cur_end = state.solver.eval(state.memory.load(vec + 8, 4, endness='Iend_LE'))
            if a + n > cur_end:
                vio = state.globals.get('oob')
                if vio is None:
                    vio = []
                    state.globals['oob'] = vio
                vio.append((state.addr, a, n, cur_end))
        except Exception:
            pass

    st.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)

    # run
    simgr = proj.factory.simulation_manager(st)
    for _ in range(20000):
        if not simgr.active:
            break
        simgr.step()
    oobs = st.globals.get('oob', [])
    print(f"ARR len={len(ints)} OOB events={len(oobs)}")
    for ev in oobs[:5]:
        pc,a,n,end = ev
        print("  OOB PC=0x%08x write [0x%08x..0x%08x) end=0x%08x" % (pc, a, a+n, end))


def main():
    proj = make_project()
    # 1) Run through JSON handler with UART-fed lines (may not always hit pad window)
    lines = LINES
    for idx, lb in enumerate(lines):
        print(f"=== Run line {idx+1}/{len(lines)} len={len(lb)} ===")
        run_line(proj, lb, slack_values=(4,6,8,10,12,14,15))
    # 2) Direct pad sweep to validate OOB detector and heap layout
    run_pad_direct_sweep(proj)
    # 3) Instrumented two-line session to trace pad and reads
    print("=== Instrumented two-line session (base=100, tail=[65,11,0]) ===")
    run_two_line_instrumented(proj, base_val=100, tail=(65,11,0), comma_space=1, trail_spaces=40)
    print("=== Instrumented two-line session (base=100, tail=[75,37,0]) ===")
    run_two_line_instrumented(proj, base_val=100, tail=(75,37,0), comma_space=1, trail_spaces=40)
    # 3a) Try seeking a heap-backed pad with increasing trailing spaces
    print("=== Heap-backed pad seek (comma_space=1, tr=0..80) ===")
    for tr in range(0, 81, 8):
        print(f"-- tr={tr} --")
        run_two_line_instrumented(proj, base_val=100, tail=(65,11,0), comma_space=1, trail_spaces=tr)
    # 3b) Direct parse-entry runs sweeping delta to force heap-backed pad
    print("=== Direct parse-entry instrumented sweep (cap=256, delta=4..10) ===")
    for d in range(4, 11):
        print(f"-- delta={d} --")
        run_parse_entry_instrumented(proj, cap=256, delta=d)
    # 3c) Combined harness: pad + immediate consumer
    print("=== Combined harness: pad + consumer (cap=256, delta=4..10) ===")
    for d in range(4, 11):
        print(f"-- delta={d} --")
        run_combined_harness(proj, cap=256, delta=d)
    # 4) Directly exercise array parser for the proven payloads
    print("=== Direct array parser tests ===")
    run_array_parser(proj, [69,2,0])
    run_array_parser(proj, ([0]*44)+[65,11,0])
    run_array_parser(proj, ([0]*44)+[75,37,0])

if __name__ == '__main__':
    main()
