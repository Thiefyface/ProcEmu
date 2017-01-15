#!/usr/bin/env python
# Experiments with Unicorn Debugger and Ptrace
#
# As of right now, just attaches to process and emulates
# from the current state of the process.
from ctypes.util import find_library
from ctypes import *
from keystone import *
from unicorn import *
from capstone import *

import multiprocessing
import argparse
import struct
import sys
import os

NULL=0

def main(): 
    fu = UniFactory()
    fu.initEmulator()
    fu.generateStandalone()

class UniFactory():

    def __init__(self):
        self.status = c_int(0)
        self.pid = -1
        self.regStruct = None
        self.proc_map = None 
        self.comms_sock = None
        self.debug_pid = 0


        if sys.maxsize > 2**32: 
            self.ks_mode = KS_MODE_64 
            self.uc_mode = UC_MODE_64
        else:
            self.ks_mode = KS_MODE_32 
            self.uc_mode = UC_MODE_64 
        
        self.ks_arch = KS_ARCH_X86
        self.uc_arch = UC_ARCH_X86
        self.uc_mode += UC_MODE_LITTLE_ENDIAN

        self.keystone = Ks(self.ks_arch,self.ks_mode) 
        self.uni = Uc(self.uc_arch,self.uc_mode) 
        self.cs = Cs(CS_ARCH_X86,CS_MODE_64)
        
    def generateStandalone(self):
        pass

    def initEmulator(self):
        parser = argparse.ArgumentParser(prog='UniFact', usage='%(prog)s [options]')
        parser.add_argument('target', help='Pid or Binary to attach/run')    
        parser.add_argument("--args", nargs="?", help="Bin args") 
        argv = parser.parse_args()
    
        uni_dict = {}
        # attach to target process
        self.pid = self.start(argv.target,argv.args)
        # get/set the registers (0 => success)
        if self.getRegs(self.pid) == 0:   
            self.output(GOOD("Registers Acquired")) 
            uni_dict= self.regStruct.get_uni_regs()
            for reg in uni_dict:
                try:
                    self.uni.reg_write(uni_dict[reg],self.regStruct.get_register(reg))
                    self.output(INFO("%s : 0x%x"%(reg,self.regStruct.get_register(reg)))) 
                except:
                    self.output(WARN("%s: unwritable"%reg))
        else:
            self.output(ERROR("Could not get Regs, exiting!"))
            sys.exit() 

        # fs/gs regs
        self.uni.mem_map(0x0,0x1000,3)
        self.uni.mem_map(0x1000,0x1000,3)
        self.uni.reg_write(uni_dict["fs"],0x800)
        self.uni.reg_write(uni_dict["gs"],0x1800)
        # hack needed for negative offset to fs...
        self.uni.mem_map(0xfffffffffffff000,0x1000,3)

        # get/set the memory mappings
        self.initMemory(self.pid)
        #self.addHooks()

        try:
            start_addr = self.regStruct.get_register("rip")
        except:
            start_addr = self.regStruct.get_register("eip")

        self.uni.hook_add(UC_HOOK_CODE,self.print_instr_hook) 
        self.uni.hook_add(UC_HOOK_MEM_INVALID,self.segfault_hook) 
        try:
            self.uni.emu_start(start_addr,-1)
        except KeyboardInterrupt:
            self.output(GOOD("Exiting!"))
        
        '''
        UC_HOOK_INTR = 1
        UC_HOOK_INSN = 2
        UC_HOOK_CODE = 4
        UC_HOOK_BLOCK = 8
        UC_HOOK_MEM_READ_UNMAPPED = 16
        UC_HOOK_MEM_WRITE_UNMAPPED = 32
        UC_HOOK_MEM_FETCH_UNMAPPED = 64
        UC_HOOK_MEM_READ_PROT = 128
        UC_HOOK_MEM_WRITE_PROT = 256
        UC_HOOK_MEM_FETCH_PROT = 512
        UC_HOOK_MEM_READ = 1024
        UC_HOOK_MEM_WRITE = 2048
        UC_HOOK_MEM_FETCH = 4096
        UC_HOOK_MEM_READ_AFTER = 8192
        UC_HOOK_MEM_UNMAPPED = 112
        UC_HOOK_MEM_PROT = 896
        UC_HOOK_MEM_READ_INVALID = 144
        UC_HOOK_MEM_WRITE_INVALID = 288
        UC_HOOK_MEM_FETCH_INVALID = 576
        UC_HOOK_MEM_INVALID = 1008
        UC_HOOK_MEM_VALID = 7168
        '''
         
    def segfault_hook(self,emulator,access,address,size,value,user_data):
        uni_dict=self.regStruct.get_uni_regs()
        for reg in uni_dict:
            val = self.uni.reg_read(uni_dict[reg])
            self.output("%s : 0x%x" % (reg,val))

        rax = self.uni.reg_read(uni_dict["rax"])
        fs = self.uni.reg_read(uni_dict["fs"])
        mem = self.uni.mem_read(fs-104,100)
        self.output("0x%x+0x%x: %s"%(fs,rax,repr(mem)))


        print "address 0x%x" % address
        print "size 0x%x" % size
        print "access 0x%x" % access
        print "value 0x%x" % value
        #print "user_data 0x%x" % user_data

    def disassemble(self,code, addr):
        tmp = ""

        for i in self.cs.disasm(str(code),addr):
            tmp_bytes = "\\x" + b'\\x'.join("%02x"%x for x in i.bytes) 
            print "%s0x%x:%s %s %s   %s%s%s" % (GREEN,i.address,CYAN,i.mnemonic,i.op_str,YELLOW,tmp_bytes,CLEAR)


    def print_instr_hook(self,emulator,address,size,user_data):
        #self.output(WARN("RIP:0x%x, SIZE:0x%x"%(address,size))) 
        code = emulator.mem_read(address,size)
        #self.output(WARN("\\x" + '\\x'.join("%02x"%x for x in code)))
        self.disassemble(code,address)


    def start(self,target,args=None):
        option = 0

        try: # attach to process
            pid = self.attach(int(target)) 
            libc.waitpid(pid,byref(self.status),option) 
            if os.WIFSTOPPED(self.status.value):         
                self.output(GOOD("Attached successfully: %s" % target)) 
            return int(target)

        except: # run process
            
            if args:
                args = _parse_args(''.join(args))
            child_pid = self.run(target,args)   

            if child_pid > 0:
                libc.waitpid(child_pid,byref(self.status),option) 
                return child_pid
            else:
                return -1
            

    # Run binary from commandline
    def run(self,targetfile,args=None):
        full_path = os.path.join(os.getcwd(),targetfile)
        # test to see if file exists first:
        if not os.path.isfile(full_path):
            self.output(ERROR("File %s does not exist!" % full_path))
            return -1
        if not os.access(full_path,os.X_OK):
            self.output(ERROR("Cannot execute file %s!" % full_path))
            return -1

        pid = libc.fork()

        #child thread
        if pid == 0:
            argv = self._parse_args(args,full_path)
            libc.ptrace(PTRACE_TRACEME,0,NULL,NULL)
            self.output(PURP("Child executing: %s" % targetfile))
            libc.execve(full_path,argv,NULL)
            
        #parent thread
        elif pid > 0:
            return pid
        #error case
        elif pid < 0:
            return -1 
    

    def _parse_args(self,args,full_path=None):
        i = 0
        try:
            argv = filter(None,args.split(" "))
            if full_path:
                argv.insert(0,full_path)
        except:
            argv = [full_path]

        c_argv = (c_char_p * len(argv))()

        for i in range(0,len(argv)):
            dir(c_argv[i])
            c_argv[i] = argv[i]

        return c_argv

    # attach to pre-existing process
    def attach(self,pid):
        pid = int(pid)
        if not os.path.isdir("/proc/%d"%pid):
            self.output(WARN("No such pid %d" % pid) )
            return

        if self.debug_pid != 0:
            WARN("Detatching from old pid: %d" % self.debug_pid)
            self.detach()

        libc.ptrace(PTRACE_ATTACH,pid,NULL,NULL)
        self.debug_pid = pid
        return pid

    ##########################        
    def detach(self):
        if self.debug_pid > 0:
            libc.ptrace(PTRACE_DETACH,self.debug_pid,NULL,0)
            self.output(INFO("Detatched from pid: %s%d"%(GREEN,self.debug_pid)))

    ##########################        
    def output(self,msg,newline=True):
       msg = str(msg)
       if newline:
           msg+="\n"
       if self.comms_sock:
           self.comms_sock.send(msg)
       else:
           sys.stdout.write(msg)
           sys.stdout.flush()

    ##########################        
    def getRegs(self,pid):
        self.regStruct = RegisterStruct()
        ret = ""

        print "" # If this is commented, PTRACE_GETREGS always returns -1. 
                 # I have no clue. Halp, gooby plz.
        self.status = libc.ptrace(PTRACE_GETREGS,pid,0,byref(self.regStruct))

        if self.status != 0:
            self.output(WARN("Error getting updated registers, pid: %d" % pid))
            self.output(WARN("Dumping last known state"))
            self.regStruct = RegisterStruct()
            return -1

        return 0


    def initMemory(self,pid):
        self.proc_map = ProcMap(pid)
        self.proc_map.update_map()

        for i in self.proc_map.get_memory_ranges():
            tmp = self.loadMemoryMap(i)

            lbound,ubound,perms,filename = i
            perms = self.rwx_to_int(perms)

            #print "Emumap: 0x%x-0x%x, len 0x%x, perm:%d - %s" % (lbound,ubound,ubound-lbound,perms,filename)
            try:
                #print "uni.mem_map(0x%x,0x%x,%d)" % (lbound,ubound-lbound,perms)
                self.uni.mem_map(lbound,ubound-lbound,perms)
                    
                if perms > 0:
                    self.uni.mem_write(lbound,tmp)
            except unicorn.UcError as e:
                #self.output(ERROR(e)) 
                continue
        

    def rwx_to_int(self,permissions):
        ret = 0
        if permissions[0] == "r":
            ret+=1
        if permissions[1] == "w":
            ret+=2
        if permissions[2] == "x":
            ret+=4
        return ret
        
    def loadMemoryMap(self,bounds):
        lbound,ubound,perm,filename = bounds

        retbuf = ""
        filename = "/proc/%d/mem"%self.debug_pid
        #self.output(GOOD("Opening %s" % filename))
        seek = True

        '''
        if os.path.isfile(filename):
            filename = filename
            seek = False
        '''

        #print seek
        #print "SEEKING:0x%x, reading 0x%x" % (bounds[0],bounds[1]-bounds[0])
        try:
            with open(filename,"rb") as f:
                if seek:
                    f.seek(lbound)

                retbuf = f.read(ubound-lbound)
            #self.output(INFO("0x%x - 0x%x" % (bounds[0],bounds[1])))
        except Exception as e:
            print e
            self.output(WARN("0x%x - 0x%x Unreadable" % (bounds[0],bounds[1])))

        return retbuf



### DEFINES ###

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSR = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSR = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24

libc = CDLL(find_library("c")) 

RED = '\001\033[31m\002'
ORANGE = '\001\033[91m\002'
GREEN = '\001\033[92m\002'
LIME = '\001\033[99m\002'
YELLOW = '\001\033[93m\002'
BLU = '\001\033[94m\002'
PURPLE = '\001\033[95m\002'
CYAN = '\033[96m'
CLEAR = '\001\033[00m\002'

def INFO(string):
    return "%s[!.!] %s%s" % (CYAN,string,CLEAR)
def ERROR(string):
    return "%s[X_X] %s%s" % (RED,string,CLEAR)
def WARN(string):
    return "%s[-.-] %s%s" % (YELLOW,string,CLEAR)
def GOOD(string):
    return "%s[^~^] %s%s" % (GREEN,string,CLEAR)
def BLUE(string):
    return "%s['.'] %s%s" % (BLU,string,CLEAR)
def PURP(string):
    return "%s[#.#] %s%s" % (PURPLE,string,CLEAR)

EFLAGS = [
       "CF", None, "PF", None, #0-3
       "AF", None, "ZF", "SF", #4-7
       "TF", "IF", "DF", "OF", #8-11
    ]


class RegisterStruct(Structure):


    
    _packed_ = 1
    if sys.maxsize <= 2**32:
        display_order = [ "eax","ebx","ecx","edx","esi","edi","esp","ebp","eip","orig_eax",
                               "eflags", "xds","xfs","xgs","xcs","xss" ]

        _fields_ = [
            ("ebx", c_ulong),
            ("ecx", c_ulong),
            ("edx", c_ulong),
            ("esi", c_ulong),
            ("edi", c_ulong),
            ("ebp", c_ulong),
            ("eax", c_ulong),
            ("xds", c_ulong),   
            ("xes", c_ulong),
            ("xfs", c_ulong),
            ("xgs", c_ulong),   
            ("orig_eax", c_ulong),
            ("eip", c_ulong),
            ("xcs", c_ulong),
            ("eflags",  c_ulong),
            ("esp", c_ulong),
            ("xss", c_ulong),
        ]

    else:

        display_order = ["rdi","rsi","rdx","rcx","r8","r9", #First 6 function params
                        "r10","r11","r12","r13","r14","r15",
                         "rax","rbx","rbp","orig_rax","rip",
                         "cs","eflags","rsp","ss","fs_base",
                        "gs_base","ds","es","fs","gs"]

        _fields_ = [
        ("r15",c_ulonglong),
        ("r14",c_ulonglong),
        ("r13",c_ulonglong),
        ("r12",c_ulonglong),
        ("rbp",c_ulonglong),
        ("rbx",c_ulonglong),
        # ^ belong to caller
        # v belong to callee
        ("r11",c_ulonglong),
        ("r10",c_ulonglong),
        ("r9",c_ulonglong),
        ("r8",c_ulonglong),
        ("rax",c_ulonglong),
        ("rcx",c_ulonglong),
        ("rdx",c_ulonglong),
        ("rsi",c_ulonglong),
        ("rdi",c_ulonglong),
        #
        ("orig_rax",c_ulonglong),
        ("rip",c_ulonglong),
        ("cs",c_ulonglong),
        ("eflags",c_ulonglong),
        ("rsp",c_ulonglong),
        ("ss",c_ulonglong),
        ("fs_base",c_ulonglong),
        ("gs_base",c_ulonglong),
        ("ds",c_ulonglong),
        ("es",c_ulonglong),
        ("fs",c_ulonglong),
        ("gs",c_ulonglong)
        ]


    def get_uni_regs(self):
        reg_dict = {}
        for reg in self.display_order:
            # tmp import...bleh
            import unicorn.x86_const as c
            reg_str = "UC_X86_REG_%s" % reg.upper()
            try:
                reg_dict[reg] = getattr(c,reg_str) 
            except:
                continue
            value = getattr(self,reg)
        return reg_dict

    def __repr__(self):
        buf=""
        for reg in self.display_order:
            value = fmtstr % getattr(self,reg)
            buf+= GREEN + "{0:10}".format(reg) + CYAN + "{0:>10}\n".format(value)
            buf += CLEAR
        return buf

    def get_stored_registers(self):
        ret=[]

        for reg in self.display_order:
            value = fmtstr % getattr(self,reg)
            ret.append((reg,value))
        return ret

    def get_register(self,reg_str):
        ret = False
        for reg,__ in self._fields_:
            if reg_str == reg:
                ret = getattr(self,reg)
        return ret

    def set_register(self,reg,value):
        ret = False
        try:
            setattr(self,reg,value)
            ret = True
        except:
            pass

        return ret

   




class MemRegion(object):
    def __init__(self,lb,ub,perm,filtered):
        
        self.lowerbound = lb
        self.upperbound = ub
        self.permissions = perm
        self.filtered = filtered


    def is_mapped(self,addr):
        try: 
            addr = int(addr,16)
        except:
            pass

        #print "0x%x-0x%x <- %s" % (self.lowerbound,self.upperbound,addr)
        if addr >= self.lowerbound and addr <= self.upperbound:
            return True

        return False
        
        

class ProcMap(object):
    def __init__(self,pid): 
        self.pid = pid
        self.memory_map = []
        self.raw_map = ""
        self.base_reloc = 0x0

        #self.mtime = 0
    
    def find_region(self,addr):
       
        for region in self.memory_map:
            if region.is_mapped(addr):
                return region
        return False

    def search_labels(self,query):
        buf = ""
        for region in self.memory_map:
            # assume label is always -1st element
            if query in region.filtered[-1]:
                buf += str(region.filtered) 
                buf += "\n"

        if len(buf):
            return buf
        else:
            return "No results"
        
    def update_map(self):
        procmap = "/proc/%d/maps" % self.pid
             
        # apparently /proc/pid/maps modtime only gets 
        # updated on x86? lol >_> 
        '''
        if os.stat(procmap).st_mtime == self.mtime:
            # not modified, no changes
            #print "No changes"
            return
            
        self.mtime = os.stat(procmap).st_mtime
        '''
        tmp = "" 
        with open(procmap,"r") as f:
            tmp = f.read()
            if self.raw_map == tmp:
                return
            self.raw_map = tmp

        self.parse_map(self.raw_map)


    def get_memory_ranges(self):
        ret_list = []
        if not self.memory_map:
            return None 
        
        #print self.memory_map
        for i in self.memory_map:
            ret_list.append((i.lowerbound,i.upperbound,i.permissions,i.filtered[-1])) 

        return ret_list

    def parse_map(self,raw_map):
        offset,dev,inode,label,extra = ("","","","","")  

        self.memory_map=[]  
        for region in filter(None,raw_map.split("\n")):
            filtered = filter(None,region.split(" "))
            try:
                bounds = filtered[0]
                perms = filtered[1]
            except:
                # badddd. Going to hit shit fast.   
                raise Exception("Unable to read /proc/pid")  

            bounds = bounds.split("-")
            lowerbound = int(bounds[0],16)
            upperbound = int(bounds[1],16)
            
            #print filtered[-1]
            self.memory_map.append(MemRegion(lowerbound,upperbound,perms,filtered))  

        
        self.base_relocation = self.memory_map[0].lowerbound
        #print "BASE RELOC: 0x%x" % self.base_relocation



if __name__ == "__main__":
    main()


'''
# just for reference
 from keystone import *

 # separate assembly instructions by ; or \n
 CODE = b"INC ecx; DEC edx"
 
 try:
   # Initialize engine in X86-32bit mode
   ks = Ks(KS_ARCH_X86, KS_MODE_32)
   encoding, count = ks.asm(CODE)
   print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
 except KsError as e:
   print("ERROR: %s" %e)
'''

