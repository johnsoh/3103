import sys

def is_hex(s):
    try:
        int(s,16)
        return True
    except ValueError:
        return False

def findOffsetLength( line ):
    i = 0
    while(True):
        if is_hex( line[i] ):
            i += 1
        else:
            return i

leftOffset=0
rightOffset=0
packetCandidate=[]
IP=0
TCP=0
UDP=0
ICMP=0
ARP=0
Ping=0
DHCP=0
DNS=0
FTP=0
NTP=0
FTPData=0
HTTP=0
#file=open('./hex.dat')
file = open (sys.argv[1])
hasPacket=False
packet = []

for line in file:
    if line == '\n' or '': 
        if len(packet)==0:
            continue
        else:
            if packet[12]+packet[13] == '0800':
                IP += 1
                #OPTIMIZATION: IPProtocol = packet[23] <-- doing this is slower
                if packet[23]=='06':
                    TCP+=1
                    if packet[34]+packet[35]=='0015' or packet[36]+packet[37]=='0015':
                        FTP+=1 
                    elif packet[34]+packet[35]=='0014' or packet[36]+packet[37]=='0014':
                        FTPData+=1
                    elif packet[34]+packet[35]=='0050' or packet[36]+packet[37]=='0050':
                        HTTP+=1                 
                elif packet[23]=='11':
                    UDP+=1
                    if packet[34]+packet[35]=='0035' or packet[36]+packet[37]=='0035':
                        DNS+=1
                    elif packet[34]+packet[35]+packet[36]+packet[37]=='00440043' or packet[34]+packet[35]+packet[36]+packet[37]=='00430044':
                        DHCP+=1
                    elif packet[34]+packet[35]=='007b' and packet[36]+packet[37]=='007b':
                        NTP+=1
                elif packet[23]=='01':
                    ICMP+=1
                    if packet[34]=='08' or packet[34]=='00':
                        Ping+=1
            elif packet[12]+packet[13] == '0806':
                ARP+=1
            packet=[]
    else: 
        if is_hex( line[0:4] ):
            if line[0:4]=='0000':
                leftOffset = len( line.split(' ')[0] ) + 2
                rightOffset = leftOffset+16*3-1
            packetCandidate=line[leftOffset:rightOffset].split(' ')
            packet=packet+packetCandidate
        else:
            continue


if packet[12]+packet[13] == '0800':
    IP += 1
    if packet[23]=='06':
        TCP+=1
    elif packet[23]=='11':
        UDP+=1
        if packet[34]+packet[35]=='0035' or packet[36]+packet[37]=='0035':
            DNS+=1
        elif packet[34]+packet[35]+packet[36]+packet[37]=='00440043' or packet[34]+packet[35]+packet[36]+packet[37]=='00430044':
            DHCP+=1
    elif packet[23]=='01':
        ICMP+=1
        if packet[34]=='08' or packet[34]=='00':
            Ping+=1
elif packet[12]+packet[13] == '0806':
    ARP+=1

print 'total number of Ethernet (IP + ARP) packets = ' +str(IP+ARP)
print 'total number of IP packets = ' + str(IP)
print 'total number of ARP packets = ' + str(ARP)
print 'total number of ICMP packets = ' + str(ICMP)
print 'total number of TCP packets = ' +str(TCP)
print 'total number of UDP packets = ' +str(UDP)
print 'total number of Ping packets = '+str(Ping)
print 'total number of DHCP packets = '+str(DHCP)
print 'total number of DNS packets = '+str(DNS)
print ''
print 'total number of HTTP packets = '+str(HTTP)
print 'total number of FTP packets = '+str(FTP)
print 'total number of FTP-DATA packets = '+str(FTPData)
print 'total number of NTP packets = '+str(NTP)

        

