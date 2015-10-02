#!/usr/bin/python

import sys, os, time
import subprocess
import argparse

class CommandContruct(): # Will be updated after getting guts of argparse.

    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.rio_path = ""          # will be used for storing path of drrun
        self.so_path = ""           # will be used for stroing path of bincov,so
        pass

    def construct(self):                # basic cmmand constrution (path, so)
        cmd = self.rio_path_contruct("")
        cmd = self.so_path_construct(cmd)
        #put_option()
        #parse_target()
        return cmd

    def rio_path_contruct(self, cmd):        # (1) take path of rio and concat. rio path in command
        self.rio_path = "./bincov/_build/bin64/drrun"    # will take path by parser in the future
        cmd = "%s" % self.rio_path
        return cmd

    def so_path_construct(self, cmd):        # (2) take path of so and concat. so path in command
        self.so_path = "./bincov/_build/clients/bincov/bin/libbincov.so"  # will take path by parser in the future
        cmd = "%s -c %s" % (cmd, self.so_path)
        return cmd

    def put_option(self, cmd, prog, covopt, tout): # It will parse the option written in cli with argparser
        cmd = "%s %s/%s/%s" % (cmd, prog, covopt, tout) # is it fastest way?
        return cmd

    def put_binpath(self, cmd, binpath):
        cmd = "%s -- %s" % (cmd, binpath)
        return cmd

    def parse_target(self): # It will parse the target written in txt with argparser
        pass 


cc = CommandContruct()
cmd = cc.construct()

# raw_input below are to be deleted.
# put_option() will substitute for it
program = raw_input("[Q. ] Enter the name of program (ex. ls) : ")
cover_option = raw_input("[Q. ] Enter the option of coverage (n : node / p : path) : ")
time_timeout = raw_input("[Q. ] Enther the time of timeout (ex. 3): ")

cmd = cc.put_option(cmd, program, cover_option, time_timeout)

# parse_target() will substitute for it.
exe_path = raw_input("[Q. ] Enter the path to execute. (ex. /bin/ls) : ")

cmd = cc.put_binpath(cmd, exe_path)

n = 0

while(True):
    print cmd
    cmd_out = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    if cmd_out[0]:
        elements = cmd_out[0].split('\n')[:-1]
        for element in elements:
            print element
    n = n+1
    print "Loop no. "+ str(n) +" is over."
    time.sleep(10)

### vim: set sts=4 sw=4 tabstop=4:
