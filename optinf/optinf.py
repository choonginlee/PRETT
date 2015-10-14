#!/usr/bin/python

import sys, os, time
import subprocess
import argparse

class CommandParse(): # Will be updated after getting guts of argparse.
    
    def __init__(self):
        self._rio_path = ""          # path of drrun
        self._so_path = ""           # path of bincov,so
        self._exe_path = ""          # path of exec file
        self._coverage  = ""
        self._timeout = 0

    def parse(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--rio", help = "Specify the path of drrun")
        parser.add_argument("-s", "--so", help = "Specify the path of so library")
        parser.add_argument("-e", "--exe", help = "Specify the path of binary to be tested")
        parser.add_argument("-p", "--path-coverage", help = "Path coverage option")
        parser.add_argument("-n", "--node-coverage", help = "Node coverage option")
        parser.add_argument("-t", "--time-out", type = int, help = "Set maximum time out count")
        args = parser.parse_args()
        
        self._rio_path = args.rio
        self._so_path = args.so
        self._exe_path = args.exe
        self._timeout = args.time_out
        if(args.path_coverage):
            self._coverage = 'n'
        elif(args.node_coverage):
            self._coverage = 'p'

    def cmd_construct(self):                # basic command constrution (path, so)
        cmd = self.rio_path_contruct("")
        cmd = self.so_path_construct(cmd)
        #put_option()
        #parse_target()
        return cmd

    def rio_path_contruct(self, cmd):        # (1) take path of rio and concat. rio path in command
        self._rio_path = "./bincov/_build/bin64/drrun"    # will take path by parser in the future
        cmd = "%s" % self._rio_path
        return cmd

    def so_path_construct(self, cmd):        # (2) take path of so and concat. so path in command
        self._so_path = "./bincov/_build/clients/bincov/bin/libbincov.so"  # will take path by parser in the future
        cmd = "%s -c %s" % (cmd, self._so_path)
        return cmd

    def put_option(self, cmd, prog, covopt, tout): # It will parse the option written in cli with argparser
        cmd = "%s %s/%s/%s" % (cmd, prog, covopt, tout) # is it fastest way?
        return cmd

    def put_binpath(self, cmd, binpath):
        cmd = "%s -- %s" % (cmd, binpath)
        return cmd

    def parse_target(self): # It will parse the target written in txt with argparser
        pass 

# raw_input below are to be deleted.
# put_option() will substitute for it
#program = raw_input("[Q. ] Enter the name of program (ex. ls) : ")
#cover_option = raw_input("[Q. ] Enter the option of coverage (n : node / p : path) : ")
#time_timeout = raw_input("[Q. ] Enther the time of timeout (ex. 3): ")

#cmd = cc.put_option(cmd, program, cover_option, time_timeout)

# parse_target() will substitute for it.
#exe_path = raw_input("[Q. ] Enter the path to execute. (ex. /bin/ls) : ")

#cmd = cc.put_binpath(cmd, exe_path)

#n = 0

def main():
    cc = CommandParse()
    cc.parse()

    pass

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

if __name__ == "__main__":
    main()

### vim: set sts=4 sw=4 tabstop=4:
