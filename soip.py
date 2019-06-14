"""########################################################
########################################################
#                                                     
# Service Oriented IP (SOIP)        
#                                                     
# Sandbox code for playing with ideas and alternatives                             
#                                                     
# Module name is 'soip'
#                                                     
# This is a toybox implementation of SOIP in 
# Python 3.6 or higher.
# It is not guaranteed or validated in any way and has
# no use except for playing with ideas.            
#
# Released under the BSD 2-Clause "Simplified" or "FreeBSD"
# License as follows:
#                                                     
# Copyright (C) 2019 Brian E. Carpenter.                  
# All rights reserved.
#
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
########################################################"""

_version = "00-BC-20190510"

##########################################################
# The following change log records significant changes,
# not small bug fixes.

# Version 00 



import sys
if sys.version_info[0] < 3 or \
   (sys.version_info[0] == 3 and sys.version_info[1]) < 4:
    raise RuntimeError("Must use Python 3.4 or later")

####################################
#                                  #
# Imports                          #
#                                  #
####################################

import time
import errno
import threading
import queue
import socket
import struct
import ipaddress
import ssl
import random
import binascii
import copy
import math
import cmath
try:
    import acp
except:
    print("Need the GRASP dummy ACP module acp.py")
    time.sleep(10)
    exit()
try:
    import tlv
except:
    print("Need the TLV module tlv.py")
    time.sleep(10)
    exit()
    
### for bubbles
try:
    import tkinter as tk
    from tkinter import font
except:
    print("Could not import tkinter. No pretty printing.")
    time.sleep(10)
###
try:
    import cbor
    #import cbor2 as cbor
except:
    print("Could not import cbor. Please do 'pip3 install cbor' and try again.")
    time.sleep(10)
    exit()

#work-around for Python system error
try:
    socket.IPPROTO_IPV6
except:
    socket.IPPROTO_IPV6 = 41

#########################################
# Handy functions
#########################################

def tname(x):
    """-> name of type of x"""
    return type(x).__name__

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')

####################################
#                                  #
# Data types and global data       #
#                                  #
####################################


####################################
# SOIP packet abstraction          #
####################################

SOIP_DEFAULT_HOP = 255
cbor_mode = True

class spacket:
    """
An SOIP packet:
 .sat    Service Action Type (integer)
 .flags  A flag byte (bytes)
 .traffic_class
 .session_id      (integer)
 .hop_limit       (integer)
 .payload_length  (integer - not used in CBOR version)
 .client          (IPv6Address)
 .service_data    (A valid Python object)
 .payload         (A valid Python object)
"""
    def __init__(self, sat):
        self.sat = sat    #type (integer)
        self.flags = 0
        self.traffic_class = 0
        self.session_id = 0
        self.hop_limit = SOIP_DEFAULT_HOP
        self.client = ipaddress.IPv6Address("::")
        self.sd_length = 0
        self.service_data = None
        self.payload_length = 0
        self.payload = None
spacket_length = len(vars(spacket(0))) #TLV case

def _set_constants(cbor_mode):
    global spacket_length
    global o_SAT, o_FL, o_TC, o_SID, o_HL, o_PLG, o_SDLG, o_CL, o_SD, o_PLD

    if cbor_mode:
        spacket_length -=2  #length fields not transmitted
    # Offsets for parsing incoming spackets
    o_SAT = 0
    o_FL = o_SAT + 1
    o_TC = o_FL + 1
    o_SID = o_TC + 1
    o_HL = o_SID + 1
    o_CL = o_HL + 1
    if cbor_mode:
        o_SDLG = o_CL   # not used in CBOR version
    else:
        o_SDLG = o_CL + 1
    o_SD = o_SDLG + 1
    if cbor_mode:
        o_PLG = o_SD   # not used in CBOR version
    else:
        o_PLG = o_SD + 1
    o_PLD = o_PLG + 1

def _pclone(pkt):
    """Internal use only"""
###################################################
# Clones a packet for local use
# If you don't use this, you may unintenionally
# modify the caller's packet (thankyou Python)
# Just do new_packet = _pclone(packet)
###################################################
    cpkt = spacket(pkt.sat)
    cpkt.flags = pkt.flags
    cpkt.traffic_class = pkt.traffic_class
    cpkt.session_id = pkt.session_id
    cpkt.hop_limit = pkt.hop_limit
    cpkt.payload_length = pkt.payload_length
    cpkt.sd_length = pkt.sd_length
    cpkt.client = pkt.client
    cpkt.service_data = pkt.service_data
    cpkt.payload = pkt.payload
    return cpkt        


####################################
# Session ID cache                 #
####################################

class _session_instance:
    """Internal use only"""
    def __init__(self, id_value, id_active, id_locator):
        self.id_value = id_value   #Integer 
        self.id_active = id_active #True if active 
        self.id_locator = id_locator #Client locator (packed)
        self.inq = None            #Queue for incoming packets

class _session_nonce:
    """Internal use only"""
    def __init__(self, id_value, id_locator):
        self.id_value = id_value   #Integer 
        self.id_locator = id_locator #Client locator (packed)

# _session_id_cache - list of _session_instance
# _sess_lock - lock for _session_id_cache

# Session_ID cache contains
#  - all currently active Session_IDs
#  - foreign source address if any
#  - status for each one (in use or inactive)
#  - as memory permits, all previously seen Session_IDs (status inactive) to avoid reuse


####################################
# Other global variables           #
#                                  #
# Reminder: any of these that get  #
# assigned inside any function or  #
# thread must be declared 'global' #
# inside that function             #
####################################

_soip_initialised = False #true after SOIP core has been initialised
_skip_dialogue = False    #true if user calls soip.skip_dialogue

# _my_address         #this node's preferred routeable address
# _my_link_local      #this node's preferred link local address
# _session_locator    #address used to disambiguate session ids
# test_mode           #True iff module is running in test mode
# is_server           #True if acting as server; False if client
# _dobubbles          #True to enable bubble printing



####################################
# SOIP protocol constants         #
####################################

# Note: there is no reasonable way to define constants in Python.
# These objects could all be overwritten by programming errors.

S_NOOP = 0      # No operation
S_IPv6 = 1      # IPv6 reachability request
S_IPv4 = 2      # IPv4 reachability request (may be implemented as IPv4-via-IPv6)
S_IP64 = 3      # IPv4/IPv6 interconnect request. This supports reachability where one address is IPv6 and the other is IPv4 (may be implemented with a NAT46 or NAT64 technique).
S_ANYC = 4      # Anycast request (for generic services)
S_COMP = 5      # Computation request
S_DWNRQ = 6     # Storage request (download content)
S_UPLRQ = 7     # Storage request (upload content)
S_MCAST = 8     # Multicast request (download multicasted content)
S_RESP = 9      # Response from server
#S_SRVR = 10     # Server solicitation (request from server)
S_INVALID = 99  # Invalid message received

SATs = [S_NOOP, S_IPv6 ,S_IPv4, S_IP64, S_ANYC, S_COMP, S_DWNRQ,
        S_UPLRQ, S_MCAST, S_RESP,
        S_INVALID] #, S_SRVR, ]

F_L0 = 0        # flag bits for flow size
F_L1 = 1
F_L2 = 2
F_MOBILE = 3    # flag bit if host is mobile
F_AUTHC = 4     # flag bit if packet authenticated
F_CRYPTO = 5    # flag bit if packet encrypted

SOIP_MAX_SIZE = 1200     # a bit less than 1280
SOIP_MAX_PAYLOAD = SOIP_MAX_SIZE - 20 #to be calculated properly!!!!!!!!
SOIP_MAX_SD = 128                     #to be calculated properly!!!!!!!!
SOIP_DEFAULT_TIMEOUT = 5 # 5 seconds
SOIP_DEFAULT_HOP = 255

SOIP_SERVER_PORT = 1021  # UDP port for server end (RFC6335)
SOIP_CLIENT_PORT = 1022  # UDP port for client end (RFC6335)

_pktQlimit = 100   # maximum size of input queue for a session
_newQlimit = 100   # maximum size of queue of new sessions
pi = math.pi       # for fun only

pattern = [8,8,8,32,8,128,'L8','L16'] #for TLV method


unspec_address = ipaddress.IPv6Address('::') # Used in special cases to indicate link local address

####################################
# Support for flag bits            #
####################################

def bit(b):
    """Internal use only"""
    # return bit b on
    return 2**b

B_MOBILE = bit(F_MOBILE)
B_AUTHC =  bit(F_AUTHC)
B_CRYPTO = bit(F_CRYPTO)


def set_flags(pkt, length, mobile, authenticated, encrypted):
    """Internal use only"""
    #set the flags word in a packet
    _f = 0
    if tname(length) == "int" and length >-1 and length <8:
        _f = length
    else:
        _f = pkt.flags&7 #keep previous length
    if mobile:
        _f |= B_MOBILE
    if authenticated:
        _f |= B_AUTHC
    if encrypted:
        _f |= B_CRYPTO
    pkt.flags = _f
    return

def get_flags(pkt):
    """Internal use only"""
    #return flags for a packet
    _f = pkt.flags
    return _f&7, bool(_f&B_MOBILE), bool(_f&B_AUTHC), bool(_f&B_CRYPTO)  

####################################
# SOIP engine internal constants  #
####################################

_sessionCacheLimit = 1000


####################################
# Error codes and English-language #
# error texts                      #
####################################

class _error_codes:
    """names and texts for the error codes"""
    def __init__(self):
        self.ok = 0
        self.noReply = 1 
        self.notSOIP = 2
        self.notCBOR = 3
        self.incLength = 4
        self.invSAT = 5
        self.invFlags = 6
        self.invTC = 7
        self.invID = 8
        self.invHops = 9
        self.invLength = 10        
        self.invIPv6 = 11
        self.invSDl = 12
        self.badSock = 13
        self.badSess = 14
        self.noQ = 15

errors = _error_codes()

etext = {errors.ok:         "OK",
         errors.noReply:    "No reply",
         errors.notSOIP:    "Not an SOIP packet",
         errors.notCBOR:    "Not valid CBOR",
         errors.incLength:  "Incorrect packet length",
         errors.invSAT:     "Invalid SAT",
         errors.invFlags:   "Invalid flags",
         errors.invTC:      "Invalid traffic class",
         errors.invID:      "Invalid session ID",
         errors.invHops:    "Invalid hop limit",
         errors.invLength:  "Invalid payload length",
         errors.invIPv6:    "Invalid IPv6 address",
         errors.invSDl:      "Invalid service data length",
         errors.badSock:    "Socket error",
         errors.badSess:    "Bad session nonce",
         errors.noQ:        "No input queue",
         
       }



####################################
#                                  
# Tell SOIP to skip initial dialogue
#                                  
####################################

def skip_dialogue(testing=False, tlving=False, bubbling=False):
    """
####################################################################
# skip_dialogue(testing=False, serving=False, tlving=False, bubbling=False)
#                                  
# Tells SOIP to skip initial dialogue
#
# Default is not test mode and not TLV and not bubbles
# Must be called before anything else
#
# No return value                                  
####################################################################
"""
    global _skip_dialogue, test_mode, cbor_mode, _dobubbles, _soip_initialised
    if _soip_initialised:
        return
    _skip_dialogue = True
    
    test_mode = testing
    cbor_mode = not tlving
    _dobubbles = bubbling


####################################
#                                  #
# Open session                     #
#                                  #
####################################

def open_session(dest=None):
    """
##############################################################
# open_session(dest=None)
#
# Open an SOIP session
#
# Note, there is no destination needed when a client sends;
# the first hop router is implicit.
#
# Non-blocking call
#
# return errorcode, session_nonce
##############################################################
"""
    global is_server
    if is_server:
        _loc = dest
    else:
        _loc = _session_locator
    _id = _new_session(_loc)

    snonce = _session_nonce(_id, _loc.packed)

    # initialise packet queue
    _s = _get_session(snonce)
    _s.inq = queue.Queue(_pktQlimit)
    _update_session(_s)

    return errors.ok, snonce

####################################
#                                  #
# Close session                    #
#                                  #
####################################

def close_session(snonce):
    """
##############################################################
# close_session(session_nonce)
#
# Close an SOIP session
#
# Note, there is no destination needed when a client sends;
# the first hop router is implicit.
#
# Non-blocking call
#
# return errorcode
##############################################################
"""
    #check that the session is real
    _s = _get_session(snonce)
    if not _s:
        return errors.badSess
    if _s.inq:
        del _s.inq   #garbage collect
        _s.inq = None
    _disactivate_session(snonce)
    return errors.ok


####################################
#                                  #
# Send packet                      #
#                                  #
####################################

def sendpkt(snonce, pkt):
    """
##############################################################
# sendpkt(session_nonce, pkt)
#
# Send an SOIP packet to the given session
#
# Non-blocking call
#
# return errorcode
##############################################################
"""
    #check that the session is real
    if not _get_session(snonce):
        return errors.badSess
    #ttprint("Sendpkt got the session")
    #check that session ID in packet matches
    if snonce.id_value != pkt.session_id:
        #ttprint(snonce.id_value,"!=",pkt.session_id)
        return errors.badSess

    if not is_server:
        #this is a client, destination is server, so...
        dest = server
        ###dest = _session_locator #Fake this to test S_SRVR anomaly case
    else:
        #this is a server, get client's address
        dest = ipaddress.IPv6Address(snonce.id_locator)
    _m = _ass_pkt(pkt)
    ttprint("Sending",len(_m),"bytes to", dest, soip_export)
    try:
        send_sock.sendto(_m,0,(str(dest), soip_export))
    except:
        return errors.badSock
    return errors.ok

####################################
#                                  #
# Receive packet                   #
#                                  #
####################################

def recvpkt(snonce, timeout):
    """
##############################################################
# recvpkt(session_nonce, timeout)
#
# Receive an SOIP packet for the given session
#
# The nonce identifies the session required
#
# Blocking call if timeout is positive (milliseconds)
#
# return errorcode, packet
##############################################################
"""
    #check that the session is real
    _s =  _get_session(snonce)
    if not _s:
        return errors.badSess, spacket(S_INVALID)
    if not _s.inq:
        return errors.noQ, spacket(S_INVALID)
    try:
        if timeout > 0:
            _pkt = _s.inq.get(block=True, timeout=timeout/1000)
        else:
            _pkt = _s.inq.get(block=False)
    except queue.Empty:
        return errors.noReply, spacket(S_INVALID)  
    return errors.ok, _pkt

##def _handle_server_sol(_pkt, _saddr):
##    """Internal use only"""
################################################################
### _handle_server_sol(_pkt, _saddr)
###
### Handle a server solicitation
###
### no return value
################################################################
##    ttprint("Handler for server solicitation")
##    #insert a session entry (no address since the other end is server)
##    sess = _session_instance(_pkt.session_id, True, None)
##    if _insert_session(sess):      
##        #send back an invalid response
##        snonce = _session_nonce(_pkt.session_id, None)
##        pkt = spacket(S_INVALID)
##        pkt.client = _session_locator
##        pkt.session_id = _pkt.session_id
##        pkt.service_data = "Invalid"
##        e = sendpkt(snonce, pkt)
##        tprint("Sent invalid response to server solicitation", etext[e])
##        #inactivate the session
##        _disactivate_session(snonce)
##        
##    else:
##        tprint("Could not insert session for server solicitation")


def _handle_client_req(_pkt, _saddr):
    """Internal use only"""
##############################################################
# _handle_client_req(_pkt, _saddr)
#
# Handle a new client request
#
# no return value
##############################################################
    ttprint("Handler for client request")
    invalid = False
    #insert a session entry
    sess = _session_instance(_pkt.session_id, True, _saddr.packed)
    if _insert_session(sess):
        snonce = _session_nonce(_pkt.session_id, _saddr.packed)
        ttprint("Made nonce", _pkt.session_id, _saddr)
##        if _pkt.sat == S_SRVR:
##            invalid = True #client sent server solicitation
##        elif _pkt.sat == S_COMP:
        if _pkt.sat == S_COMP:
            #pretend computation request
            ttprint("Payload", _pkt.payload)
            try:
                response = str(eval(_pkt.payload)) #evaluate the computation
                pkt = spacket(S_RESP)
                pkt.client = _saddr
                pkt.session_id = _pkt.session_id
                pkt.payload_length = len(response) #bogus for now
                pkt.payload = response
                e = sendpkt(snonce, pkt)
                ttprint("Sent computation response to client", etext[e])
            except:
                invalid = True #couldn't evaluate
        else:
            pass #other SATs TBD

        if invalid:
            #send back an invalid response           
            pkt = spacket(S_INVALID)
            pkt.client = _saddr
            pkt.session_id = _pkt.session_id
            pkt.service_data = "Invalid"
            e = sendpkt(snonce, pkt)
            tprint("Sent invalid response to client request", etext[e])

        #we're done, inactivate the session
        _disactivate_session(snonce)
        
    else:
        tprint("Could not insert session for client request")
    
 

####################################
#                                  #
# Internal functions               #
#                                  #
####################################

def hexit(xx):
    """Internal use only"""
    if tname(xx) == "bytes":
        return binascii.b2a_hex(xx)
    elif tname(xx) == "list":
        for i in range(len(xx)):
            xx[i] = hexit(xx[i])            
    return(xx)


def tprint(*whatever,ttp=False):
    """Multi-thread printing, used exactly like print()"""
    #first get the module name
    a,b = str(threading.current_thread()).split('<')
    a,b = b.split('(')  
    _print_lock.acquire()
    #print module name and thread ID
    print(a,threading.get_ident(),end=" ",flush=False)
    _s=""
    #print whatever
    for x in whatever:
        try:
            if test_mode:           #want bytes printed in hex
                xx=copy.deepcopy(x) #avoid overwriting anything
                xx = hexit(xx)
            else:
                xx=x               
            _s=_s+str(xx)+" "
            print(xx,end=" ",flush=False)
        except:
            #in case UTF-8 string can't be printed
            print("[unprintable]",end="",flush=False)
    print("")

    if _dobubbles and not ttp:
        #Queue the text for bubble printing
        if len(_s) > 200:
            _s = _s[:200]+' ...' #truncate to fit
        try:
            bubbleQ.put(_s, block=False)
        except:
            pass   # Skip it if queue is full
    _print_lock.release()
    return


def ttprint(*whatever):
    """Multi-thread printing in test mode only, used exactly like print()"""

    if test_mode:
        tprint(*whatever,ttp=True)
    return

######################################
#
# Package to speak in bubbles
#
######################################

    
def init_bubble_text(cap):
    """
    Switch on bubble printing, which uses tkinter
    cap: a string that labels the bubble window.
    """

#------------
# Classes and functions

    class speakEasy:
        """Simple class to describe a message

        x, y: (int) anchor point for the message
        txt: (string) text of the message
        i: after drawing, canvas item for image
        j: after drawing, canvas item for text"""
        
        def __init__(self, x, y, txt):
            self.x = x     #coordinates
            self.y = y
            self.txt = txt #words

    def draw_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """
        global _bubblim, _myfont

        #print("Drawing x",bubble.x,"y",bubble.y,"text",bubble.txt)
        pos = (bubble.x, bubble.y)
        
        bubble.i=can.create_image((bubble.x, bubble.y), image=_bubblim)
        
        bubble.j=can.create_text((bubble.x-180,bubble.y-80), font=_myfont,
                             text=bubble.txt, anchor=tk.NW,width=_wrap_at)


    def raise_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """
        bubble.y -=step
        can.move(bubble.i,0,-step)
        can.move(bubble.j,0,-step)
        return

    class bubbler(threading.Thread):
        """Internal use only"""
        def __init__(self, cap):
            threading.Thread.__init__(self)
            self.cap = cap
            
        def run(self):

            global _dobubbles, _bubblim, _logoim, _myfont, _wrap_at, _bigstring, _bigstring2
            
            try:
                #make a window
                #Validate caption first
                _c=self.cap
                if _c == "":
                    _c=" GRASP" #default caption if blank
                elif _c[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    _c = " "+_c #get round 'feature' in Tk
                root = tk.Tk(className=_c)
                
                #make images and a font
                _bubblim = tk.PhotoImage(data=_bigstring)
                _logoim = tk.PhotoImage(data=_bigstring2)
                del _bigstring
                del _bigstring2
                _myfont = font.Font(family='Arial',size=12,weight='bold')
                
                #set an icon
                root.tk.call('wm', 'iconphoto', root._w, _logoim)

                #window on top (doesn't work in all cases)
                root.lift()
         
                #size the window
                root.geometry(str(HEIGHT)+"x"+str(WIDTH))

                #make a canvas
                can = tk.Canvas(root)  
                can.config(background=backgroundCol) #colour it
                can.pack(fill=tk.BOTH, expand=1) #always full size        
                
                #draw blank canvas
                root.update_idletasks()
                root.update()
                bubbles = [] # empty message list
                _looping = True
                _pause = 0
            except:
                tprint("Could not start Tkinter")
                _looping = False

            while _looping:
                
                # Check print queue unless pausing
                if _pause <= 0:
                    try:
                        _tx = bubbleQ.get(block=False)
                    
                        #Build a bubble
                        _m=speakEasy(random.randrange(250,270),int(HEIGHT-70),_tx)

                        #Raise existing bubbles
                        for i in range(len(bubbles)):
                            if i==len(bubbles)-1:
                                #Extra raise for the most recent
                                raise_bubble(can,bubbles[i])
                            raise_bubble(can,bubbles[i])

                        #Draw the new one
                        draw_bubble(can,_m)
                        #Add new one to the display list
                        bubbles.append(_m)

                        #Delete the oldest one if off screen
                        if bubbles[0].y<-2*step:
                            can.delete(bubbles[0].i)
                            can.delete(bubbles[0].j)
                            del bubbles[0]
                        #tprint(len(bubbles),"bubbles now")

                        #Ask for a display pause
                        _pause = int(FRAMERATE/2)
                    except:
                        pass

                #Decrement pause
                if _pause > 0:
                    _pause -= 1
                
                #Update our display                
                if bubbles != []:
                    try:
                        root.update_idletasks()
                        root.update()
                    except:
                        _looping=False #Somebody closed the window

                # Wait before next loop
                time.sleep(1/FRAMERATE)

            #Exiting
            tprint("Bubbles over")
            _dobubbles = False
                
    #--------------
    # constants and global vars
    global _dobubbles, _bubblim, _myfont, _wrap_at
            
    WIDTH = 500
    HEIGHT = 500
    _wrap_at = 350 #width for text wrap
    step = 50 #how much to raise a bubble each time
    FRAMERATE = 10
    #make a random colour for the background
    r=random.randrange(1,255)
    g=random.randrange(1,255)
    b=random.randrange(1,255)
    backgroundCol="#{0:02x}{1:02x}{2:02x}".format(r,g,b)
    bubbles = []
    _bubblim = None
    _logoim = None
    _myfont = None
    _dobubbles = True
    #start a thread to do the work
    bubbler(cap).start()
    
    return




####################################
# Session ID cache functions       #
####################################

_prng = random.SystemRandom() # best PRNG we can get
def _new_session(locator):
    """Internal use only"""
####################################
# Create and insert a new Session  
# in state active, local           
# _new_session(locator) returns integer    
####################################
    _sess_lock.acquire()
    for i in range(10):
        x = _prng.randint(0, 0xffffffff)
        # does _session_id_cache contain an id_value = x?
        if not([clash for clash in _session_id_cache if clash.id_value == x]):
            if locator == None:
                _session_id_cache.append(_session_instance(x,True,None))
            else:
                _session_id_cache.append(_session_instance(x,True,locator.packed))
            _sess_lock.release()
            return x
    # If we're here, something is deeply suspect and we have to give up.
    raise RuntimeError("Ten successive pseudo-random session ID clashes")




def _insert_session(session_inst, _check_race = False):
    """Internal use only"""
####################################
# Insert a Session ID entry        #
#                                  #
# return True if successful        #
#                                  #
# set _check_race to check for     #
# race condition                   #
####################################
    new_id = session_inst.id_value
    #check for a clash
    _sess_lock.acquire()
    
    if ([clash for clash in _session_id_cache if clash.id_value == new_id]):
        # duplicate, need to check source address
        _sess_lock.release()
        if _check_race:
            return False # incredibly unlikely race condition, do nothing
        clash = _get_session(_session_nonce(new_id,session_inst.id_locator))
        #the following test is because in theory the session could have
        #just been deleted by another thread...
        if clash:
            if clash.id_locator == session_inst.id_locator:
                #now we have a confirmed clash, cannot continue
                return False
        #duplicate has a different source address (or it vanished)
        #so we can continue
        _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    if session_ct >= _sessionCacheLimit:
        # try to free a space
        for i in range(session_ct):
            if not _session_id_cache[i].id_active:
                # found first inactive entry - delete it and append new one
                del _session_id_cache[i]
                _session_id_cache.append(session_inst)
                _sess_lock.release()
                return True
        # no free space, fail
        tprint("Session cache overflow!")
        _sess_lock.release()
        return False
    else:
        #append new one
        _session_id_cache.append(session_inst)
        _sess_lock.release()
        return True



def _get_session(snonce):
    """Internal use only"""
####################################
# Get a Session ID entry by ID and #
# source locator                   # 
#                                  #
# _get_session(_session_nonce)     #
# return False if not found active #
# else return _session_instance    #
####################################   
    _sess_lock.acquire()
    for s in _session_id_cache:
        if snonce.id_value == s.id_value and snonce.id_locator == s.id_locator and s.id_active:
            _sess_lock.release()
            return s
    _sess_lock.release()
    return False



def _update_session(session_inst):
    """Internal use only"""
####################################
# Update a Session ID entry        #
#                                  #
# return True if successful        #
####################################
    old_id = session_inst.id_value
    old_src = session_inst.id_locator
    _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    for i in range(session_ct):
        if old_id == _session_id_cache[i].id_value and old_src == _session_id_cache[i].id_locator:
            _session_id_cache[i] = session_inst
            _sess_lock.release()
            return True
    #no such ID/source, fail
    _sess_lock.release()
    return False



def _disactivate_session(snonce):
    """Internal use only"""
####################################
# Disactivate a Session ID entry   #
#                                  #
# parameter is _session_nonce      #
#                                  #
# ignores mismatch                 #
# returns nothing                  #
####################################
    s = _get_session(snonce)
    if s:
        s.id_active = False
        _update_session(s)
    return

#########################################
#########################################
# Assemble and serialise outbound packet
#########################################
#########################################

def _ass_pkt(pkt):
    """Internal use only"""
    global cbor_mode, pattern
    _msg = bytes([0x70])
    if cbor_mode:
        # does not encode payload_length  and sd_length
        _msg += cbor.dumps((pkt.sat, pkt.flags, pkt.traffic_class, pkt.session_id,
                           pkt.hop_limit, pkt.client.packed,
                           pkt.service_data, pkt.payload))
    else:
        # encode everything
        _msg += tlv.dumps(pattern,
                          pkt.sat, pkt.flags, pkt.traffic_class, pkt.session_id,
                          pkt.hop_limit, pkt.client.packed,
                          tlv.lv(8*pkt.sd_length, pkt.service_data),
                          tlv.lv(8*pkt.payload_length, pkt.payload))                          
    return _msg
    
#########################################
#########################################
# Disassemble & Pythonise inbound packet
# with validity checks
#########################################
#########################################

def _dis_pkt(raw):
    """Internal use only"""
    global cbor_mode, pattern
    if raw[0] != 0x70:
        return errors.notSOIP, None
    if cbor_mode:
        try:
            _decode = cbor.loads(raw[1:])
        except:
            return errors.notCBOR, None
    else:
        _decode = tlv.expand_tuples(tlv.loads(pattern, raw[1:]))   
        #convert some fields to integer
        for _f in (o_SAT, o_FL, o_TC, o_SID, o_HL):
            _decode[_f] = int_from_bytes(_decode[_f])
    ttprint("Decoded packet",_decode)
    if len(_decode) != spacket_length:
        return errors.incLength, None
    if tname(_decode[o_SAT]) != "int":
        return errors.invSAT, None
    if not _decode[o_SAT] in SATs:
        return errors.invSAT, None
    _pkt = spacket(_decode[o_SAT])
    if tname(_decode[o_FL]) != "int":
        return errors.invFlags, None
    if _decode[o_FL] <0 or _decode[o_FL] > 255:
        return errors.invFlags, None
    _pkt.flags = _decode[o_FL]
    if tname(_decode[o_TC]) != "int":
        return errors.invTC, None
    if _decode[o_TC] <0 or _decode[o_TC] > 255:
        return errors.invTC, None
    _pkt.traffic_class = _decode[o_TC]
    if tname(_decode[o_SID]) != "int":
        return errors.invID, None
    _pkt.session_id = _decode[o_SID]
    if tname(_decode[o_HL]) != "int":
        return errors.invHops, None
    if _decode[o_HL] <0 or _decode[o_HL] > 255:
        return errors.invHops, None
    _pkt.hop_limit  = _decode[o_HL] 
       
    try:
        _pkt.client = ipaddress.IPv6Address(_decode[o_CL])
    except:
        return errors.invIPv6, None
    
    if not cbor_mode:
        if _decode[o_SDLG] <0 or _decode[o_SDLG] > SOIP_MAX_SD:
            return errors.invSDl, None
        _pkt.sd_length = _decode[o_SDLG]    
    _pkt.service_data = _decode[o_SD]
    
    if not cbor_mode:
        if _decode[o_PLG] <0 or _decode[o_PLG] > SOIP_MAX_PAYLOAD:
            return errors.invLength, None
        _pkt.payload_length = _decode[o_PLG]
    _pkt.payload = _decode[o_PLD]
    #ttprint("Returning spacket OK", _pkt)
    return errors.ok, _pkt
    
    
class _udp_listen(threading.Thread):
    """Internal use only"""
#########################################################
# UDP listener thread for incoming packets              #
#########################################################
    def __init__(self):
        threading.Thread.__init__(self)


    def run(self):

        listen_sock=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(('',soip_inport))
        listen_sock.settimeout(None) #listener will block

        # For ever, wait for incoming packets and queue them
        # for the listening session (if any).
        tprint("UDP listener is up on port", listen_sock.getsockname()[1])
        while True:
            rawmsg, send_addr = listen_sock.recvfrom(SOIP_MAX_SIZE)
            if '%' in send_addr[0]:
                a,b = send_addr[0].split('%') #strip any Zone ID
            else:
                a = send_addr[0]
            send_addr=ipaddress.IPv6Address(a)
            ttprint("Received UDP", rawmsg, "from", send_addr)
            err, pkt = _dis_pkt(rawmsg)
            if err:
                tprint("Received bad packet", etext[err])
                ttprint("Raw message:", rawmsg)
            else:
                #queue the packet for its session
                snonce = _session_nonce(pkt.session_id, send_addr.packed)
                #ttprint("Matching", pkt.session_id, send_addr.packed)
                session = _get_session(snonce)
                if not session:
                    ttprint("Received packet for unknown session")
                    ttprint("Session ID", pkt.session_id, ", sender", send_addr)
                    #queue the packet for new session handler
                    newq.put((pkt, send_addr))
                elif session.inq:
                    session.inq.put(pkt)
                else:
                    ttprint("Received packet for session with no queue")
                    ttprint("Session ID", pkt.session_id)
                        
  
# end of UDP listener

class _new_listen(threading.Thread):
    """Internal use only"""
#########################################################
# listener thread for new sessions                      #
#########################################################
    def __init__(self):
        threading.Thread.__init__(self)


    def run(self):
        # For ever, wait for incoming sessions
        tprint("New session listener is up.")
        while True:
            _pkt, _saddr = newq.get(block=True)
            ttprint("Got new session from", _saddr)
            #dump_pkt(_pkt)
            if is_server:
                _handle_client_req(_pkt, _saddr)
            else:
                # client
                if _pkt.sat == S_RESP:
                    tprint("Client received response to unknown session")
                else:
                    tprint("Client received unexpected SAT", _pkt.sat)
##                elif _pkt.sat != S_SRVR:
##                    tprint("Client received unexpected SAT (not Server solicitation)")
##                else:
##                    _handle_server_sol(_pkt, _saddr)
            

def dump_pkt(p):
    """
    ####################################################
    # dump a packet's header if in test mode
    ####################################################
    """
    ttprint("SAT", p.sat, ", Flags", p.flags, ", Traffic class", p.traffic_class,
            "\nSession ID", p.session_id, ", Hop limit", p.hop_limit,
            "\nClient", p.client)
    # p.payload_length, p.service_data and p.payload not printed


def dump_all():
    """
    ####################################################
    # dump_all() prints the various data structures   
    #                                                 
    # Intended only for interactive debugging         
    # and not thread-safe                             
    ####################################################
    """
    print("\nThread count:",threading.active_count(),"\n------------")
    print("\nMy address:", str(_my_address),"\n----------")
    print("\nSession locator:", str(_session_locator),"\n---------------")
    print("\nSession ID cache contents:\n-------------------------")         
    for x in _session_id_cache:
        print("Nonce:",'{:8}'.format(x.id_value),"Client:",
              ipaddress.IPv6Address(x.id_locator),
              "Active:",x.id_active)
   


def initialise_soip(serving=False):
    """General initialisation. 
    Should only be called once per instance of SOIP."""

    ####################################
    # Should we even be here?          #
    ####################################
    
    global _soip_initialised
    if _soip_initialised:
        return
    
    ####################################
    # Declare all global variables     #
    # (a necessary nuisance)           #
    ####################################

    global _session_id_cache
    global _sess_lock
    global _print_lock
    global _my_address
    global _my_link_local
    global _session_locator
    global _skip_dialogue
    global test_mode
    global is_server
    global server
    global mess_check
    global _make_invalid
    global _make_badmess
    global _dobubbles
    global soip_inport
    global soip_export
    global send_sock
    global soip_inport
    global soip_export
    global cbor_mode

    ####################################
    ####################################
    #                                  #
    # Start of main initialisation     #
    #                                  #
    ####################################
    ####################################


    tprint("WARNING: This is toybox code for the SOIP protocol.")
    tprint("It is unsuitable for operational purposes.")
    tprint("Use it at your own risk!")
    tprint("Python SOIP Version",_version,"released under the")
    tprint("simplified BSD license.")
    tprint("Will use port numbers", SOIP_SERVER_PORT, "and", SOIP_CLIENT_PORT)

    if not _skip_dialogue:
    
        ####################################
        # Run in test mode?                # 
        ####################################

        test_mode = False          # Set this True for prolix diagnostic prints
                                   # and some special case tests.
                                   # Leave it False for "production" mode.
        try:
            _l = input("Test mode (many extra diagnostics)? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    test_mode = True
        except:
            pass

        ####################################
        # Run in TLV mode?                # 
        ####################################

        cbor_mode = True          # Set this False for TLV instead of CBOR
                                  
        try:
            _l = input("TLV mode? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    cbor_mode = False
        except:
            pass

    ####################################
    # Client or server?                # 
    ####################################

    is_server = serving

    if is_server:
        soip_inport = SOIP_SERVER_PORT
        soip_export = SOIP_CLIENT_PORT
        _capst = "SOIP Server"
    else:
        soip_inport = SOIP_CLIENT_PORT
        soip_export = SOIP_SERVER_PORT
        _capst = "SOIP Client"

    server = ipaddress.IPv6Address(socket.getaddrinfo("server.soip.local",0)[0][4][0])
        
    ####################################
    # Initialise global variables      #
    #                                  #
    # Reminder: any of these that get  #
    # written before read inside any   #
    # function or thread must be       #
    # declared 'global' inside that    #
    # function.                        #
    ####################################

    _set_constants(cbor_mode)
     
    _sess_lock = threading.Lock()   # Create and acquire lock
    _sess_lock.acquire()


    _session_id_cache = []      # empty list of _session_instance
    _sess_lock.release()        # release lock
 
    _make_invalid = False      # For testing invalid message, with care
    _make_badmess = False      # For testing bad message format, with care
                           
    tprint("Initialised global variables and session cache.")


    ####################################
    # What's my address?               #
    ####################################

    #Borrow this from the GRASP world...

    _my_address = acp._get_my_address(build_zone=False)
 
    if _my_address == None:
        tprint("Could not find a valid global IPv6 address, will generate a bogon for session disambiguation")
        _p = bytes.fromhex('20010db8f000baaaf000baaa')       #96 bits of prefix
        _x = struct.pack('!L', _prng.randint(0, 2147483647)) #32 bits of randomness
        _session_locator = ipaddress.IPv6Address(_p+_x)
    else:
        if not (_my_address.is_private and not _my_address.is_link_local):
            tprint("WARNING: address is not ULA")
        _session_locator = _my_address
        
    tprint("My global scope address:", str(_my_address))
    tprint("Session locator:", str(_session_locator))
    if not is_server:
        tprint("Server locator:", str(server))
 


    ####################################
    # Start threads to listen for and  #
    # queue SOIP packets, and to await #
    # new sessions                     #
    ####################################

    _udp_listen().start()
    ttprint("Set up UDP listening")
    _new_listen().start()
    ttprint("Set up new session handler")

    ####################################
    # Create socket to send            #
    # SOIP packets                     #
    ####################################

    send_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #ensure that we send from desired address
    send_sock.bind((str(_my_address),0))
    ttprint("Set up UDP sending socket")


    ####################################
    # SOIP initialisation complete!    #
    ####################################
    init_bubble_text(_capst)
    time.sleep(2) # to avoid printing glitch
    _soip_initialised = True
    tprint("SOIP startup function exiting")

####################################
# Create globals needed for initialisation
####################################

_print_lock = threading.Lock() # printing might be needed before init!
test_mode = False              # referenced by skip_dialogue(), used by printing
listen_self = False            # referenced by skip_dialogue()
_skip_dialogue = False         # referenced by skip_dialogue()
_dobubbles = True              # bubble print by default
bubbleQ = queue.Queue(100)     # Will be used if bubble printing

newq = queue.Queue(_newQlimit) # Queue for packets that start new sessions

#------------------------------------------------------------
# The following are the GIF images used for the bubble printing
# mechanism. They are placed here only to avoid distraction
# elsewhere. Don't edit them! There's nothing significant below

_bigstring="""
R0lGODlhwgHIAOcAAAAAAAEBAQICAgMDAwQEBAUFBQYGBgcHBwgICAkJCQoKCgsLCwwMDA0NDQ4O
Dg8PDxAQEBERERISEhMTExQUFBUVFRYWFhcXFxgYGBkZGRoaGhsbGxwcHB0dHR4eHh8fHyAgICEh
ISIiIiMjIyQkJCUlJSYmJicnJygoKCkpKSoqKisrKywsLC0tLS4uLi8vLzAwMDExMTIyMjMzMzQ0
NDU1NTY2Njc3Nzg4ODk5OTo6Ojs7Ozw8PD09PT4+Pj8/P0BAQEFBQUJCQkNDQ0REREVFRUZGRkdH
R0hISElJSUpKSktLS0xMTE1NTU5OTk9PT1BQUFFRUVJSUlNTU1RUVFVVVVZWVldXV1hYWFlZWVpa
WltbW1xcXF1dXV5eXl9fX2BgYGFhYWJiYmNjY2RkZGVlZWZmZmdnZ2hoaGlpaWpqamtra2xsbG1t
bW5ubm9vb3BwcHFxcXJycnNzc3R0dHV1dXZ2dnd3d3h4eHl5eXp6ent7e3x8fH19fX5+fn9/f4CA
gIGBgYKCgoODg4SEhIWFhYaGhoeHh4iIiImJiYqKiouLi4yMjI2NjY6Ojo+Pj5CQkJGRkZKSkpOT
k5SUlJWVlZaWlpeXl5iYmJmZmZqampubm5ycnJ2dnZ6enp+fn6CgoKGhoaKioqOjo6SkpKWlpaam
pqenp6ioqKmpqaqqqqurq6ysrK2tra6urq+vr7CwsLGxsbKysrOzs7S0tLW1tba2tre3t7i4uLm5
ubq6uru7u7y8vL29vb6+vr+/v8DAwMHBwcLCwsPDw8TExMXFxcbGxsfHx8jIyMnJycrKysvLy8zM
zM3Nzc7Ozs/Pz9DQ0NHR0dLS0tPT09TU1NXV1dbW1tfX19jY2NnZ2dra2tvb29zc3N3d3d7e3t/f
3+Dg4OHh4eLi4uPj4+Tk5OXl5ebm5ufn5+jo6Onp6erq6uvr6+zs7O3t7e7u7u/v7/Dw8PHx8fLy
8vPz8/T09PX19fb29vf39/j4+Pn5+fr6+vv7+/z8/P39/f7+/v///yH+EUNyZWF0ZWQgd2l0aCBH
SU1QACH5BAEKAO8ALAAAAADCAcgAAAj+AN8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mix
o8ePIEOKHEmypMmTKFOqXMmypcuXMGPKnEmzps2bOHPq3Mmzp8+fQIMKHUq0qNGjSJMqXcq0qdOn
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"""

_bigstring2="""
R0lGODlh6wBnAeMIAAAAACMjI0dHR2lpaYmJiaenp8PDw93d3f//////////////////////////
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"""

#---------------The End ----------------------------------------------------
