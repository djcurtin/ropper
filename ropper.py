#!/usr/bin/python3 -i

import re
import sys
import copy

#: Functions from here to the multi-# break are responsible for loading
#: the specified files, and parsing them into a dictionary of usable
#: gadgets.

#: Gadget dictionary is { address: [ops] } where 
#: 1. address is as specified in RP++ output. 
#: 2. ops is a list, split on the " ; " separating them

#: Loop through input files, compiling a big list of gadgets.
#: Remove the (1 found) at the end of each line, and filter out unwanted stuff.
#: Then turn the list of lines into the gadget dict and return that
def load_files():
    lines = []
    for filename in sys.argv[1:]:
        with open(filename, "r") as f:
            for line in f:
                tmp = line.strip()
                if "(" in tmp:
                    tmp = tmp.split(" (")[0]
                lines.append(tmp)

    lines = filter_lines(lines)
    gadgets = parse_gadgets(lines)
    return gadgets

#: Gets rid of stuff we do not want.
#: 1. Remove duplicates by converting to set and back to list
#: 2. Run through op_filter function to remove the rest of unwanted stuff
def filter_lines(lines):
    lines = [ *set(lines) ]
    lines = list( filter(op_filter, lines) )
    return lines

#: Simple, yet somewhat ugly, but it does a lot.
#: 1. Remove lines which do not start with an address ("0x")
#: 2. retn 0x04 and retn 0x08 are usable. Get rid of anything higher than 0x08
#: 3. Remove lines containing bad ops as specified in the list below.
#:    a. Anything that messes with control flow (call, jmp, loop, etc)
#:    b. Anything that messes with ESP
def op_filter(line):
    if is_unusable_gadget(line):
        return False

    if contains_big_retn(line):
        return False

    if contains_bad_ops(line):
        return False

    return True

#: Performs a few checks to determine whether line contains an unusable gadget
#: Line is unusable when:
#: 1. It does not contain a gadget (no address)
#: 2. It contains a gadget of only 1 op, which is useless
#:
#: Tricky return because function returns true if line is NOT usable.
def is_unusable_gadget(line):
    has_no_address = not ("0x" == line[0:2])
    has_no_ops     = not (" ; " in line)

    return (has_no_address or has_no_ops)

#: Do not want bit retn 0x... values because it will screw up the stack
#: 0x04, 0x08 and 0x0C are acceptable. Anything greater needs to go.
def contains_big_retn(line):
    # (= 12 in decimal, or 3 dwords)
    max_retn = 0x0C 

    end = line.split(" ; ")[-1]
    if "retn 0x" == end[0:7]:
        value = int(end.split(" ")[1], 16)
        if value > max_retn:
            return True
    else:
        #: Can't have big retn if there is no retn
        return False

#: Quick loop through list of bad ops. Return true if one found in gadget
def contains_bad_ops(line):
    bad_ops = ['call', 'leave', 'add esp, 0x', 'loop', 'loopne',
               'jmp', 'jz', 'je', 'jnz', 'jne', 'ja', 'jae', 
               'jna', 'jnae', 'jb', 'jbe', 'jnb', 'jnbe']

    for op in bad_ops:
        if op in line:
            return True

    return False

#: Lines are in the form of address: op1 ; op2 ; ...
#: Split on ": " to get address and ops
#: Then split ops on " ; " to get address, [ops]
#: Then convert them to dict of {address: [ops]} and return
def parse_gadgets(lines):
    gadgets = {}
    for line in lines:
        address, ops = line.split(": ")
        ops = ops.split(" ; ")
        #: Remove the (1 found) at the end of the line, if there
        if '(' in ops[-1]:
            ops[-1] = ops[-1].split(' ')[0]
        gadgets[address] = copy.copy(ops)

    return gadgets

################################################################################

#: Define global variables
eax, ebx, ecx, edx = ["eax", "ebx", "ecx", "edx"]
edi, esi, ebp, esp = ["edi", "esi", "ebp", "esp"]
g = {}

#: Load gadgets into default variable
g = load_files()
print("Gadgets loaded into variable g\n")

################################################################################

#: Searching functions
#: These functions build a search regex and send it along to gadget_match

#: Find gadgets which dereference a pointer. For example:
#: 1. mov eax, dword [eax]
def deref(gadgets=g, max_len=0):
    ops = [ "mov", "add", "sub", "or", "and" ]
    dst = [ "e.." ]
    src = [ r"[^\[]*\[e..\]" ]

    seek  = "^(" + "|".join(ops) + ") *"
    seek += "(" + "|".join(dst) + "), *"
    seek += "(" + "|".join(src) + ")"

    matches = gadget_match(gadgets, seek, max_len)

    return matches

#: Find gadgets which move value from src to dst.
#: Move-like features are acceptable. For example:
#: 1. mov eax, ebx
#: 2. push ebx ; pop eax
#:
#: Note: add and or both work if dst is 0x00
#:       sub works if src is negative of the desired value
#:       and works if dst is 0xffffffff
def mov(dst, src, gadgets=g, max_len=0):
    matches = []
    ops = [ "mov", "add", "sub", "or", "and", "xchg" ]

    seek  = "^(" + "|".join(ops) + ") *"
    seek += dst + ", *" + src

    matches  = gadget_match(gadgets, seek, max_len)
    matches += push_pop(src, dst, gadgets, max_len)

    return matches

#: Find gadgets which can be used to increase a register's value
#: 1. inc eax
#: 2. add eax, 0x04
#: 3. sub eax, ebx (assuming ebx is negative)
def inc(reg, gadgets=g, max_len=0):
    matches = []
    ops = [ "add", "sub", "inc" ]

    seek  = "^(" + "|".join(ops) + ") *"
    seek += reg

    matches = gadget_match(gadgets, seek, max_len)

    return matches

#: Find gadgets which help put the value of esp into any other register
def get_sp(gadgets=g, max_len=0):
    return mov("e..", "esp", gadgets, max_len=max_len)

#: Find gadgets which push src and pop dst
#: Tries to loop over gadgets to ensure value popped into dst is pushed src
def push_pop(src, dst, gadgets=g, max_len=0):
    matches = []
    pushes = push(src, gadgets, max_len)
    if len(pushes) > 0:
        ga   = { addr: gadgets[addr] for addr in pushes }
        pops = pop(dst, ga, max_len)

        ga = { addr: ga[addr] for addr in pops }
        matches = check_push_pops(ga, src, dst)

    return matches

#: Find gadgets which push a value
#: Can't see this being useful without also finding a pop to dest register
def push(reg, gadgets=g, max_len=0):
    seek = "push %s" % reg
    pushes = gadget_match(gadgets, seek, max_len)
    return pushes

#: Find gadgets which pop into a register
def pop(reg, gadgets=g, max_len=0):
    seek = "pop %s" % reg
    pops = gadget_match(gadgets, seek, max_len)
    return pops

#: Loops over push/pop gadget to make sure pushed src ends up popped to dst
def check_push_pops(gadgets, src, dst):
    matches = []
    for addr, ops in gadgets.items():
        pushed = []
        for op in ops:
            try:
                cmd, reg = op.split(" ")
            except ValueError:
                continue
            cmd = cmd.strip()
            if cmd == "push":
                reg = reg.strip()
                pushed.append(reg)
            elif cmd == "pop":
                if len(pushed) > 0:
                    tmp = pushed.pop()
                    if (re.match(src, tmp)):
                        reg = reg.strip()
                        if (re.match(dst, reg)):
                            matches.append(addr)
                            break

    return matches

#: Loop through gadgets to find ops which match the seek regex condition
#: Return list of addresses (gadget dict keys) which match
def gadget_match(gadgets, seek, max_len=0):
    matches = []

    if max_len > 0:
        for addr, rops in gadgets.items():
            #: len rops - 1 because ending ret counts as a gadget
            if (len(rops) - 1) <= max_len:
                for rop in rops:
                    if re.match(seek, rop):
                        matches.append(addr)
    else:
        for addr, rops in gadgets.items():
            for rop in rops:
                if re.match(seek, rop):
                    matches.append(addr)

    return matches

#: Clean printing of gadgets
def gp(addresses, gadgets=g):
    index = 0
    for addr in addresses:
        print("%02d. %s: %s" % (index, addr, " ; ".join(gadgets[addr])))
        index = index + 1

#: gp but with gadgets matching remove (regex) removed
def cp(addresses, remove, gadgets=g):
    index = 0
    for addr in addresses:
        if bad_at_addr(g[addr], remove):
            continue
        else:
            print("%02d. %s: %s" % (index, addr, " ; ".join(gadgets[addr])))
            index = index + 1

def bad_at_addr(gadgets, re_bad):
    for g in gadgets:
        if re.search(re_bad, g):
            return True

    return False

def help():
    helpstring = (
        "deref(g, max_len)             : Find dereferences\n"
        "get_sp(g, max_len)            : Find gadgets to get stack pointer\n"
        "mov(src, dst, g, max_len)     : Find gadgets to move src to dest\n"
        "pop(reg, g, max_len)          : Find gadgets used to push reg\n"
        "push(reg, g, max_len)         : Find gadgets used to pop reg\n"
        "push_pop(src, dst, g, max_len): Find gadgets to move src to dest\n"
        "help()                        : Print this message\n"
        "\ngp(address_array, g)        : Print gadgets\n"
        "cp(address_array, remove, g)  : gp but with remove (regex) grepped out\n"
    )
    print(helpstring)


help()









