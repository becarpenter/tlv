import soip
import time
import math
pi=math.pi
soip.initialise_soip()
p=soip.spacket(soip.S_COMP)

#time1 = time.process_time()
while True:
#for _ in range(100):
    calc = input("Enter arithmetic expression:")
    #calc = "2+2"
    soip.tprint("Sending", calc)
    p.payload = calc
    p.payload_length = len(p.payload) #harmless but not used in CBOR version

    e,s=soip.open_session(soip._session_locator)
    soip.ttprint("Open", soip.etext[e])

    p.client = soip._session_locator
    p.session_id = s.id_value
    soip.ttprint("Session ID", s.id_value)
    e=soip.sendpkt(s,p)

    soip.ttprint("Sending computation request", calc, soip.etext[e])

    e,q=soip.recvpkt(s,1000)
    soip.ttprint("Received", soip.etext[e],q.session_id,q.client,q.service_data,q.payload)
    if e:
        soip.tprint("Error", soip.etext[e])
    elif q.sat == soip.S_INVALID:
        soip.tprint("Invalid") 
    else:
        if soip.tname(q.payload) == 'bytes':
            q.payload = q.payload.decode('utf-8')
        if float(q.payload) != eval(calc):
            soip.tprint("Result =", q.payload, "should be", eval(calc))
        else:
            soip.tprint("Result =", q.payload)
#time2 = time.process_time()
#soip.tprint("CPU time",int(1000*(time2-time1)),"milliseconds")
