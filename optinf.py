import sys, os, time
import subprocess

def build_syntax_prog(cmd, prog, covopt, tout):
    cmd = cmd + " %s/%s/%s" % (prog, covopt, tout)
    return cmd

def build_syntax_exe(cmd, ex_file):
    cmd = cmd + " -- " + ex_file
    return cmd

cmd = "./bincov/_build/bin64/drrun -c ./bincov/_build/clients/bincov/bin/libbincov.so"

program = raw_input("[Q. ] Enter the name of program (ex. ls) : ")
cover_option = raw_input("[Q. ] Enter the option of coverage (n : node / p : path) : ")
time_timeout = raw_input("[Q. ] Enther the time of timeout (ex. 3): ")

cmd = build_syntax_prog(cmd, program, cover_option, time_timeout)

exe_path = raw_input("[Q. ] Enter the path to execute. (ex. /bin/ls) : ")

cmd = build_syntax_exe(cmd, exe_path)
git 
n = 0

while(True):
    cmd_out = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    if cmd_out[0]:
        elements = cmd_out[0].split('\n')[:-1]
        for element in elements:
            print element
    n = n+1
    print "Loop no. "+ str(n) +" is over."
    time.sleep(10)


