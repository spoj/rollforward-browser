# The guest helper: runs in the signed-in session (started at sign-in), serves the host over the virtio-serial
# port, one JSON request per line, one reply per line, in order.
import base64
import ctypes
import datetime
import json
import os
import subprocess
import sys
import tempfile
import time

PORT = r'\\.\Global\org.machines.0'
WORK = r'C:\work'
PYTHON = os.path.join(os.path.dirname(sys.executable), 'python.exe')
NO_WINDOW = subprocess.CREATE_NO_WINDOW


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ushort) for n in ('year', 'month', 'weekday', 'day', 'hour', 'minute', 'second', 'ms')]


def set_time(utc):
    t = datetime.datetime.fromisoformat(utc).astimezone(datetime.timezone.utc)
    if not ctypes.windll.kernel32.SetSystemTime(ctypes.byref(SYSTEMTIME(t.year, t.month, 0, t.day, t.hour, t.minute, t.second, t.microsecond // 1000))):
        raise ctypes.WinError()


def run(lang, script, timeout_s):
    path = os.path.join(tempfile.mkdtemp(), 'script.py' if lang == 'python' else 'script.ps1')
    if lang == 'python':
        cmd = [PYTHON, path]
    else:
        script = '[Console]::OutputEncoding = [Text.Encoding]::UTF8\n' + script
        cmd = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path]
    with open(path, 'w', encoding='utf-8' if lang == 'python' else 'utf-8-sig') as f:
        f.write(script)
    p = subprocess.Popen(cmd, cwd=WORK, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         creationflags=NO_WINDOW, env={**os.environ, 'PYTHONUTF8': '1'})
    try:
        out, err = p.communicate(timeout=timeout_s)
        result = {'exit': p.returncode}
    except subprocess.TimeoutExpired:
        subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], capture_output=True, creationflags=NO_WINDOW)
        out, err = p.communicate()
        result = {'exit': None, 'timed_out': True}
    return {**result, 'stdout': out.decode('utf-8', 'replace'), 'stderr': err.decode('utf-8', 'replace')}


def handle(msg):
    op = msg['op']
    if op == 'ping':
        return {}
    if op == 'time':
        set_time(msg['utc'])
        return {}
    if op == 'run':
        return run(msg['lang'], msg['script'], msg['timeout_s'])
    if op == 'put':
        os.makedirs(os.path.dirname(msg['path']), exist_ok=True)
        with open(msg['path'], 'wb') as f:
            f.write(base64.b64decode(msg['data']))
        return {}
    if op == 'get':
        with open(msg['path'], 'rb') as f:
            return {'data': base64.b64encode(f.read()).decode()}
    raise ValueError(f'unknown op {op}')


def serve(port):
    buf = b''
    while True:
        chunk = port.read(1 << 20)
        if not chunk:
            time.sleep(0.05)
            continue
        buf += chunk
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            msg = {}
            try:
                msg = json.loads(line)
                reply = handle(msg)
            except Exception as e:
                reply = {'error': f'{type(e).__name__}: {e}'}
            data = memoryview(json.dumps({'id': msg.get('id'), **reply}).encode() + b'\n')
            while data:
                data = data[port.write(data):]


while True:
    try:
        with open(PORT, 'r+b', buffering=0) as port:
            serve(port)
    except OSError:
        time.sleep(1)
