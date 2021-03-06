import os
import sys
import time
import struct
import signal
import glob
import argparse
import zmq
import tempfile
from pathlib import Path

print("starting up", file=sys.stderr)

QEMU_PATH = os.path.dirname(os.path.realpath(__file__))+"/afl-qemu-trace"

#each input is stored here
Path('/dev/shm/coverage/').mkdir(parents=True, exist_ok=True)
INPUT_FILE = str(Path(tempfile.mkdtemp(dir='/dev/shm/coverage/'))/"coverage_input")


parser = argparse.ArgumentParser(description='Fast Forkserver Base Binary Coverage')
 
parser.add_argument('-o', metavar='output_folder',
                    help='Where to store the trace files', default=None)
parser.add_argument('-m', metavar='wordize',choices=["32","64"],
                    help='Architecture to use for QEMU', required=True)
parser.add_argument('-z', metavar="zmq_url", required=True,
                    help='zmq url which sends jobs and where results are returned')
parser.add_argument('-t', nargs='?', metavar="timeout", const=1.0,
                    default=1.0, type=float, help='Timeout in seconds')
parser.add_argument('cmd', metavar="...", nargs=argparse.REMAINDER,
                    help = 'Command to run, @@ is replaced by input file')


def replace_input(f, filepath):
    if f == "@@":
        return filepath
    else:
        return f


args = parser.parse_args()
ARGS = [replace_input(f,INPUT_FILE) for f in args.cmd]
OUTDIR = args.o or tempfile.mkdtemp()
QEMU_PATH += "_"+args.m
TIMEOUT = args.t
ZMQ_URL = args.z
HIDE_OUTPUT = True

def handle_timeout(pid):
    print("got timeout", file=sys.stderr)
    sys.stderr.flush()
    os.kill(pid, signal.SIGKILL)

class Forkserver:
    def __init__(self):
        self.ctl_out, self.ctl_in = os.pipe()
        self.st_out, self.st_in = os.pipe()
        self.in_file = open(INPUT_FILE, "wb+")

        fork_pid = os.fork()
        if fork_pid < 0:
            print("failed fork", file=sys.stderr)
            raise RuntimeError("Failed to fork child")
        if fork_pid == 0:
            self.child()
        else:
            self.parent()

    def child(self):
        FORKSRV_FD = 198 # from AFL config.h
        os.dup2(self.ctl_out, FORKSRV_FD)
        os.dup2(self.st_in, FORKSRV_FD+1)

        if HIDE_OUTPUT:
            null = open("/dev/null","w")
            null_fd = null.fileno()
            os.dup2(null_fd, 1)
            os.dup2(null_fd, 2)
            null.close()

        os.dup2(self.in_file.fileno(),0)
        os.close(self.in_file.fileno())

        os.close(self.ctl_in)
        os.close(self.ctl_out)
        os.close(self.st_in)
        os.close(self.st_out)
        env = {"TRACE_OUT_DIR": OUTDIR,
               "QEMU_LOG": "nochain",
               } 
        os.execve(QEMU_PATH,["afl-qemu-trace"]+ARGS, env)
        print("child failed", file=sys.stderr)

    def parent(self):
        os.close(self.ctl_out)
        os.close(self.st_in)
        os.read(self.st_out, 4)

    def run(self, testcase):
        self.in_file.truncate(0)
        self.in_file.seek(0)
        self.in_file.write(testcase)
        self.in_file.seek(0)

        os.write(self.ctl_in, b"\0\0\0\0")

        pid = struct.unpack("I", os.read(self.st_out, 4))[0]

        signal.signal(signal.SIGALRM, lambda signum,sigfr : handle_timeout(pid))
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT, 0)
        while True:
            try:
                status = os.read(self.st_out, 4)
            except OSError:
                continue
            break
        signal.setitimer(signal.ITIMER_REAL, 0, 0) # disable timer for timeout
        if status:
            status = struct.unpack("I",status)[0]
        return status

context = zmq.Context.instance()
socket = context.socket(zmq.DEALER)
socket.setsockopt(zmq.IDENTITY, f'T_{os.getpid()}'.encode())
socket.connect(ZMQ_URL)

print("starting coverage forkserver", file=sys.stderr)
sys.stderr.flush()
frk = Forkserver()
while True:
    socket.send_multipart([b'T_UP'])
    time.sleep(0.2)
    try:
        socket.recv_multipart(zmq.NOBLOCK)
    except zmq.error.Again:
        continue
    break

last_check = time.time()
while True:
    msg = socket.recv_multipart()
    msg_type = msg[0]
    if msg_type == b"DIE":
        break
    elif msg_type == b"TRACE":
        tries = 1
        while True:
            path = msg[1]
            with open(path, 'rb') as f:
                res = frk.run(f.read())%256  # posix return code is mod 256
                if res != 0:
                    time.sleep(0.1)
                    if tries >= 3:
                        print("path failed -", "res:", res, "tries:", tries, "path:", path, flush=True)
                        break
                    tries += 1
                    continue
                traces = []
                for trace in glob.glob(OUTDIR+"/trace_thread_*.qemu"):
                    with open(trace, 'rb') as t:
                        traces.append(t.read())
                    os.unlink(trace)
            socket.send_multipart([b'T_TR', path, *traces])
            break
    else:
        print(f"Unknown message: {msg}", file=sys.stderr)

    # if traces_per_second > 0 and last_check+1 < time.time():
    #     print(f"traces/s: {traces_per_second}", file=sys.stderr)
    #     sys.stderr.flush()
    #     traces_per_second = 0
    #     last_check = time.time()

socket.close(linger=0)
context.destroy(linger=0)
