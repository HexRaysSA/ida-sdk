
# This script can be used to reproduce crashes from ida.log files
# It defines a function named repro(), which can be used like this:
#       repro('ida.log')

import traceback
import importlib
import ida_kernwin

def repro(idalog):
    idaapi.cvar.batch = True
    skip = True
    fillog = False
    if "_filtered" in idalog:
        fillog = True
    imported = {}
    print('### Running fuzzer results from ' + idalog)
    with open(idalog, 'r') as fp:
        for line in fp.readlines():
            if skip:
                if line.find('You may start to explore') != -1:
                    if not fillog:
                        with open(str(idalog) + "_filtered.log", 'w') as newlog:
                            newlog.write(idalog + "\n")
                            newlog.write(line + "\n")
                            newlog.close()
                    with open(str(idalog) + "_nonfiltered.log", 'w') as log:
                        log.write(idalog + "\n")
                        log.write(line + "\n")
                        log.close()
                    skip = False # found the last line printed by ida before fuzzing
                continue

            line = line.rstrip()
            if len(line) == 0:
                continue

            # import the module if not done yet
            comma = line.find('.')
            if comma != -1:
                modname = line[:comma]
                if modname not in imported:
                    try:
                        imported[modname] = 1
                        print('import ' + modname)
                        globals()[modname] = importlib.import_module(modname)
                    except:
                        pass

            print(line)
            try:
                if line[0] != "#":
                    eval(line)
                if not fillog:
                    with open(str(idalog) + "_filtered.log", 'a') as newlog:
                        newlog.write(line + "\n")
                        newlog.close()
                with open(str(idalog) + "_nonfiltered.log", 'a') as log:
                    log.write(line + "\n")
                    log.close()
            except Exception as e:
                if not fillog:
                    with open(str(idalog) + "_nonfiltered.log", 'a') as log:
                        log.write(line + "\n")
                        log.close()
                print('%s\n%s' % (str(e), traceback.format_exc()))
    idaapi.cvar.batch = False

path = ida_kernwin.ask_file(False, '*.log', 'Please select a log file')
if path is not None:
    repro(path)

