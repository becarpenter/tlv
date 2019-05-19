"""########################################################
#                                                     
# tlv module - Type Length Value encode/decode
#
# The main API is the tlv.dumps() and tlv.loads() functions
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License (details in source file).
#
# Version 20190520
#                                                     
# Copyright (C) 2019 Brian E. Carpenter.                  
# All rights reserved.
########################################################
"""

########################################################
########################################################
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.                                  
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A     
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)    
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING   
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        
# POSSIBILITY OF SUCH DAMAGE.                         
#                                                     
########################################################
########################################################

import sys
if sys.version_info[0] < 3 or \
   (sys.version_info[0] == 3 and sys.version_info[1]) < 4:
    raise RuntimeError("Must use Python 3.4 or later")

import binascii

# Coding note:
# Bits in a byte are numbered from 0 (least significant) to
# 7 (most significant). Bytes objects are padded at the left
# (most significant) if necessary. But the wire order is big-endian,
# or network byte order, which would number from 0 (most significant).

class lv:
    """A length/value pair for use in a classical TLV format"""
    def __init__(self, l, v):
        self.l = l    #length (integer)
        self.v = v    #value (int, bytes, bool or str)

class tlv:
    """A type/length/value triple for use in a classical TLV format"""
    def __init__(self, t, l, v):
        self.t = t    #type (integer)
        self.l = l    #length (integer)
        self.v = v    #value (int, bytes, bool or str)

def pattern():
    """
#####################################
# In the dumps() and loads() calls, a
# TLV pattern is the first parameter.
#####################################
#
# The pattern is a list of sizes in bits. For example [8,8]
# means that 2 objects will each be encoded in one byte,
# and the resulting byte string will be 2 bytes long.
# For 'dumps' the objects may be int (>=0, max 2**32-1),
# bytes, Boolean (1 bit) or UTF-8 str.
# For 'loads' all objects except Booleans are returned as bytes; 
# the user must cast them as int or str if needed.

# A (length, value) duple may be encoded # as an 'lv' object.
# In that case the entry in the pattern is the string 'L8'
# for an 8 bit length and 'L16' for a 16 bit length. 
# (Other lengths not currently supported.)

# A (type, length, value) triple may be encoded as a 'tlv' object.
# In that case the entry in the pattern is the string 'T8L8'
# for an 8 bit length and value, or 'T8L16', 'T16L8' or 'T16L16'
# for other combinations. (Other lengths not currently supported.)

# An object of size 0 in the pattern is skipped in 'dumps'
# and returned as 'None' in 'loads'. This is to allow TLV
# tuples with no value, or any other missing field, to be
# handled uniformly

# Here are some example patterns:
#
# [8,16,8,1] - three integers and a Boolean
# [8,1,16,1,8] - integer, Boolean, 2-character string, Boolean, integer
# [8,1,'L8',1,8] - integer, Boolean, an LV duple, Boolean, integer
#
# The LV duple could be, e.g., tlv.lv(32,123456) or tlv.lv(32,'abcd')
#
# [8,'T8L16',1] - integer, TLV triple, Boolean
#
# The TLV triple could be tlv.tlv(17,32,123456)
#
# Note on Booleans: If you want a fully encoded byte, that's
# going to be 8 Booleans [1,1,1,1,1,1,1,1]. But the module allows
# any number of consecutive Booleans in the pattern, and bit shifts
# all subsequent items accordingly, with zero bits to pad the end.
# It's *much* more efficient to put 8 Booleans in a row!
#
# Beware! For strings, the length must be the length in bits, which
# in a UTF-8 string is not the same as 8 times the string length.
# Thus, for example, tlv.lv(32,"300€") is a mistake.
"""
    #this function is a dummy to attach documentation
    return
    

def loads(pattern, raw):
    """Loads Python objects from raw TLV bytes; returns a list of objects"""
    stuff = []
    nextbit = 0
    for nbits in pattern:
        if nbits in ('L8','L16'):
            #we have a length, value duple coming
            ll = int(nbits[1:])          #size of length field
            l = int_from_bytes(_load_it(nextbit, ll, raw)) #get the length
            #print("l",l,"ll",ll)
            nextbit += ll
            v = _load_it(nextbit, l, raw) #get the value
            stuff.append(lv(l,v))         #append the LV duple
            nextbit += l
        elif nbits in ('T8L8','T8L16','T16L8','T16L16'):
            #we have a TLV coming
            ts, ls = nbits[1:].split('L')
            tt = int(ts)          #size of type field
            t = int_from_bytes(_load_it(nextbit, tt, raw)) #get the type
            #print("t",t,"tt",tt)
            nextbit += tt
            ll = int(ls)          #size of length field
            l = int_from_bytes(_load_it(nextbit, ll, raw)) #get the length
            #print("l",l,"ll",ll)
            nextbit += ll
            v = _load_it(nextbit, l, raw) #get the value
            stuff.append(tlv(t,l,v))      #append the TLV
            nextbit += l
            
        else:
            stuff.append(_load_it(nextbit, nbits, raw))          
            nextbit += nbits
        #print(stuff)
    return stuff

def _load_it(nextbit, nbits, raw):    
    """Internal use only"""
    if nbits == 0:
        return None
    #extract next n bits from raw as a bytes object
    elif nbits%8 == 0 and nextbit%8 == 0:
        #byte aligned, easy case
        #print(nextbit,nbits)
        b = raw[nextbit//8:(nextbit+nbits)//8]
        return b
    else:
        if nbits == 1:
            #Boolean
            b = raw[nextbit//8] & _bits[7-nextbit%8]
            #print("bool",b)
            return bool(b)
        else:
            b = bytes.fromhex('00')
            #print("Starting at",nextbit)
            rawbit = nextbit
            objbit = 7-nbits%8  #pad at the left
            #go one bit at a time
            for j in range(0, nbits):                       
                if raw[rawbit//8] & _bits[7-rawbit%8]:
                    #print("j", j, "rawbit", rawbit,"objbit",objbit)
                    b = b[:-1] + int_to_bytes(b[-1]| _bits[objbit%8])
                rawbit += 1
                objbit -= 1
                if objbit < 0 and j < nbits-1:
                    objbit = 7
                    b = b + bytes.fromhex('00')
                    #print("Added a byte")
            return b

def dumps(pattern, *stuff):
    """Dumps Python objects to TLV bytes; returns a bytes object"""
    raw = bytes.fromhex('')  # empty bytes object
    bits_in = 0              # how many bits have we added?
    i = 0                    # position in the pattern
    for thing in stuff:
        try:
            nbits = pattern[i]
        except:
            raise RuntimeError("TLV pattern too short")
        #print(nbits, thing)
        if nbits in ('L8','L16'):
            #we have a length, value pair
            #output the length field
            ll = int(nbits[1:])
            l = thing.l
            bits_in, raw = _dump_it(bits_in, ll, l, raw)
            #set up to output the value
            nbits = thing.l
            thing = thing.v

        if nbits in ('T8L8','T8L16','T16L8','T16L16'):
            #we have a TLV
            ts, ls = nbits[1:].split('L')
            #output the type field
            tt = int(ts)
            t = thing.t
            bits_in, raw = _dump_it(bits_in, tt, t, raw)
            #output the length field
            ll = int(ls)
            l = thing.l
            bits_in, raw = _dump_it(bits_in, ll, l, raw)
            #set up to output the value
            nbits = thing.l
            thing = thing.v
            

        #now dump the actual value
        bits_in, raw = _dump_it(bits_in, nbits, thing, raw)

        # next entry in pattern  
        i += 1
    return raw

def _dump_it(bits_in, nbits, thing, raw):
    """Internal use only"""
    if nbits == 0:
        #don't care what the thing is, skip it
        pass
    else:
        _t = tname(thing)
        if _t not in ("int","bytes","str","bool"):
            raise RuntimeError("TLV cannot encode "+_t)
        if _t == "int":
            if thing < 0:
                raise RuntimeError("TLV cannot encode negative integer")
            thing = int_to_bytes(thing)
            if len(thing) > 4:
                raise RuntimeError("TLV cannot encode integer > 2**32-1")
        elif _t == "bool":
            if nbits != 1:
                raise RuntimeError("TLV requires length 1 for Boolean")
            if thing:
                thing = bytes.fromhex('01') #left-padded
            else:
                thing = bytes.fromhex('00')
        elif _t == "str":
            thing = thing.encode('utf-8')
        # thing is now bytes
        tbits = len(thing)*8
        if tbits == nbits:
            #correct length, nothing to check
            pass
        elif (tbits > nbits) and (_t != "bool"):
            #too long - is it ok to truncate?
            diff = tbits-nbits
            #print(diff)
            for j in range(0, diff):
                if bit(j, thing):
                    raise RuntimeError("Object too large for TLV field")
            #truncate to nearest byte
            thing = thing[diff//8:]
        else:
            #too short - insert leading bytes as needed
            while len(thing)*8 < nbits:
                thing = bytes.fromhex('00')+thing
        #thing is ready, but we might not be at a byte boundary
        if bits_in%8 == 0 and nbits%8 == 0:
            #all byte aligned, the easy case
            raw = raw + thing
            bits_in += 8*len(thing)
        else:
            #go one bit at a time
            #point to first bit in thing
            k = (nbits-1)%8
            for j in range(0, nbits):
                #print("bits_in",bits_in,"nbits",nbits,"j",j,"k",k,"len",len(thing))
                if bits_in%8 == 0:
                    #new byte needed
                    raw += bytes.fromhex('00')
                    #print("Added a byte")
                if thing[j//8] & _bits[k%8]:
                    #print("nbits", nbits, "bits_in", bits_in, "target bit",bits[7-bits_in%8])
                    raw = raw[:-1] + int_to_bytes(raw[-1]| _bits[7-bits_in%8])
                bits_in += 1
                k -=1
                if k < 0:
                    k = 7
            #print("bits_in now",bits_in)
    return bits_in, raw

def expand_tuples(decode):
    """Expand the tuples in a loaded object list; returns a list of objects"""
    expanded = []
    for p in decode:
        if tname(p) == 'lv':
            expanded.append(p.l)
            expanded.append(p.v)
        elif tname(p) == 'tlv':
            expanded.append(p.t)
            expanded.append(p.l)
            expanded.append(p.v)
        else:
            expanded.append(p)
    return expanded
            


#########################################
# Handy functions
#########################################

def tname(x):
    """-> name of type of x"""
    return type(x).__name__

def int_to_bytes(x):
    """integer -> bytes object"""
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes):
    """bytes object -> integer"""
    return int.from_bytes(xbytes, 'big')

_bits = (1,2,4,8,16,32,64,128)

def bit(j, thing):
    """ -> Boolean value of jth bit of thing """
    if thing[j//8] & _bits[j%8]:
        return True
    else:
        return False


def hexit(xx):
    """Returns bytes object(s) as hex strings for printout"""
    yy = []
    if tname(xx) == "bytes":
        return binascii.b2a_hex(xx)
    elif tname(xx) == "list":
        yy = []
        for i in range(len(xx)):
            yy.append(hexit(xx[i]))
    elif tname(xx) == "tuple":
        yy = ()
        for i in range(len(xx)):
            yy = yy + (hexit(xx[i]),)
    return(yy)


