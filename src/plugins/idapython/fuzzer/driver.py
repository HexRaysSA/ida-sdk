#! /usr/bin/python

# IDAPython fuzzer for IDA

import io
import os
import sys
import time
import subprocess
import threading
import shutil
import re
import string
import signal

binary = 'shorty'
script = '../fuzzer.py'
workdir = 'tmp'
resdir  = 'results'
seen_calls = {}
crash_lock = threading.Lock()
exiting = False

#----------------------------------------------------------------------------
def sigint_handler(sig, frame):
  exiting = True
  print('Fuzzer exiting after Ctrl+C')
  mylog('----------------------------------- CTRL-C HAS BEEN DETECTED ----\n')
  sys.exit(0)

#----------------------------------------------------------------------------
def switch_to_workdir():
  if not os.path.exists(resdir):
    os.mkdir(resdir)
  if not os.path.exists(workdir):
    os.mkdir(workdir)
  os.chdir(workdir)

#----------------------------------------------------------------------------
def read_last_line(logfile):
  try:
    f = open(logfile)
    fsize = f.seek(0, io.SEEK_END)
    fpos = fsize - 200 if fsize >= 200 else 0
    f.seek(fpos, io.SEEK_SET)
    for line in f:
      if line.find('decompiling') == -1 and \
         line.find('Decompile') == -1 and \
         line.find('Unloading') == -1 and \
         line.find('Flushing') == -1 and \
         line.find('Cannot close file') == -1 and \
         line.find('autoanalysis has finished') == -1 and \
         line != '' and \
         line.find('trying to store') == -1:
        last_line = line
    f.close()
    return last_line
  except:
    return ''

#----------------------------------------------------------------------------
def mylog(s):
  stamp = time.strftime('%F %T ')
  print(stamp + s)

#----------------------------------------------------------------------------
def get_called_func(line):
  idx = line.find('(')
  if idx != -1:
    line = line[:idx]
  return line

#----------------------------------------------------------------------------
def run(i, serial):
  global seen_calls
  dest = binary + '_' + str(i)
  shutil.copy('../'+binary, dest)
  logfile = 'ida'+str(serial)+'.log'
  temp_logfile = 'running_' + logfile
  p = subprocess.run(['idat64', '-c', '-L'+temp_logfile, '-A', '-S' + script, dest])
  if exiting:
    return
#  print('IDA at slot %d exited with %d (serial %d)' % (i, p.returncode, serial))
  last_line = read_last_line(temp_logfile)
  idx = last_line.find('.')
  if idx != -1:
    sfx = last_line[:idx]
  else:
    sfx = 'ida_'
  logfile = '../' + resdir + '/' + sfx + '_' + str(serial) + '.log'
  os.rename(temp_logfile, logfile)
  with crash_lock:
    new_size = os.path.getsize(logfile)
    called_func = get_called_func(last_line)
    if called_func not in seen_calls:
      mylog('Found new case size=%d %s' % (new_size, logfile))
      seen_calls[called_func] = logfile
      fp = open('../crash.log', 'a')
      fp.write(last_line + '\n')
      fp.close()
    else:
      old_log = seen_calls[called_func]
      old_size = os.path.getsize(old_log)
      if new_size < old_size:
        file_to_delete = old_log
        seen_calls[called_func] = logfile
        mylog('Shortened case size=%d old=%d %s' % (new_size, old_size, logfile))
      else:
        file_to_delete = logfile
      os.remove(file_to_delete)
    os.remove(dest)
    sys.exit(1)

#----------------------------------------------------------------------------
def main():
  signal.signal(signal.SIGINT, sigint_handler)
  switch_to_workdir()
  ncpus = os.cpu_count()
  running = [None] * ncpus
  serial = 0
  while not exiting:
    for (i, t) in enumerate(running):
      if t is None:
        serial = serial + 1
        t = threading.Thread(target=run, args=(i,serial))
        running[i] = t
        t.start()
      t.join(timeout=0)
      if not t.is_alive():
        running[i] = None
    time.sleep(0.1)

#----------------------------------------------------------------------------
try:
  main()
except KeyboardInterrupt:
  sigint_handler(None, None)
