# author: Artur Hubert
# Date: 21.10.2016
import subprocess
import binascii
import socket
import sys
import re

FORMAT_INFO_USER_SPECIFIED = 0
FORMAT_INFO_32FLOAT        = 1
FORMAT_INFO_32INTEGER      = 2
FORMAT_INFO_24INTEGER      = 3
FORMAT_INFO_16INTEGER      = 4

format_info_vals ={
    FORMAT_INFO_USER_SPECIFIED:        "User specified",
    FORMAT_INFO_32FLOAT:               "32bit.f",
    FORMAT_INFO_32INTEGER:             "32bit.i",
    FORMAT_INFO_24INTEGER:             "24bit.i",
    FORMAT_INFO_16INTEGER:             "16bit.i",
    0:                                 "ts"
}


SAMPLE_RATE_USER_SPECIFIED = 0
SAMPLE_RATE_8K             = 1
SAMPLE_RATE_16K            = 2
SAMPLE_RATE_32K            = 3
SAMPLE_RATE_44K1           = 4
SAMPLE_RATE_48K            = 5
SAMPLE_RATE_88K2           = 6
SAMPLE_RATE_96K            = 7
SAMPLE_RATE_176K4          = 8
SAMPLE_RATE_192K           = 9
SAMPLE_RATE_16RPM          = 10
SAMPLE_RATE_33RPM3         = 11
SAMPLE_RATE_33RPM3_REV     = 12
SAMPLE_RATE_45RPM          = 13
SAMPLE_RATE_78RPM          = 14
SAMPLE_RATE_RESERVED       = 15

sample_rate_type_vals = {
    SAMPLE_RATE_USER_SPECIFIED:        "User specified",
    SAMPLE_RATE_8K:                    "8kHz",
    SAMPLE_RATE_16K:                   "16kHz",
    SAMPLE_RATE_32K:                   "32kHz",
    SAMPLE_RATE_44K1:                  "44.1kHz",
    SAMPLE_RATE_48K:                   "48kHz",
    SAMPLE_RATE_88K2:                  "88.2kHz",
    SAMPLE_RATE_96K:                   "96kHz",
    SAMPLE_RATE_176K4:                 "176.4kHz",
    SAMPLE_RATE_192K:                  "192kHz",
    SAMPLE_RATE_16RPM:                 "24kHz",
    SAMPLE_RATE_33RPM3:                "33 1-3 RPM",
    SAMPLE_RATE_33RPM3_REV:            "33 1-3 RPM In Reverse",
    SAMPLE_RATE_45RPM:                 "45RPM",
    SAMPLE_RATE_78RPM:                 "78RPM",
    SAMPLE_RATE_RESERVED:              "Reserved",
    0:                                 "mpeg"
}

class Stream(object):
    def __init__(self, sid=None, fmt=None, chs=None, smr=None, cmd=None, type=None):
        self.sid  = sid    # stream id
        self.fmt  = fmt    # format 16bit
        self.chs  = chs    # number of channels
        self.smr  = smr    # sample rate
        self.cmd  = cmd    # command for extracting payload data from stream
        self.type = type   # stream type, a = audio, v = video tv / ts stream

class AVBExtractor(object):
    #Class extracting avb data from file of type t, version of thshark v
    cmdStreams = []
    cmdData = ''
    def __init__(self, file=None, type=None, ver=None, exe=None):
        self.file = file    # file to extract data from
        self.type = type    # type to be extracted audio or video
        self.ver  = ver     # version of wireshark installed
        self.cmdStreams = []
        self.cmdData = ''
        afds = ['stream_id', 'format_info', 'channels_per_frame', 'nominal_sample_rate']
        vfds = ['stream_id', 'fmt', 'svfield', 'verfield']
        TsCmd = exe + ' -r '
        strFds = ''
        pref = ''
        if type == 'audio':
            if ver == "OLD":
                pref = 'ieee1722a.' #prefix for avb data fields
            elif ver == "NEW":
                pref = 'aaf.' #prefix for avb data fields
            for f in afds:
                strFds = strFds + ' -e ' + pref + f
            self.cmdStreams.insert(0,TsCmd + file + ' -T fields' + strFds)
            self.cmdData = TsCmd + file + ' -T fields -e ' + pref + 'data ' + pref + 'stream_id == '
        elif type == 'video':
            pref = 'ieee1722.'
            for f in vfds:
                strFds = strFds + ' -e ' + pref + f
            self.cmdStreams.insert(0,TsCmd + file + ' -T fields' + strFds + ' ' + pref + 'subtype == 0x00')
            self.cmdData = TsCmd + file + ' -T fields -e ' + pref + 'data ' + pref + 'subtype == 0x00 and ' + pref + 'stream_id == '

    def get_streams(self):
        slst = []
        for cmd in self.cmdStreams:
            #print cmd
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                l = line.split('\t')
                if len(l) == 4:
                    if len(l[0])>0:
                        found = 0
                        for stream in slst:
                            if l[0] in stream.sid:
                                found = 1
                                break;
                        if found == 0:
                            self.cmdData = self.cmdData + l[0] + ' | tr -d \'\\n\\t\\r:, \''
                            if self.type == 'video': # todo remove this ugly hack
                                slst.append(Stream (l[0], 0, 0, 0, self.cmdData, self.type))
                            else:
                                slst.append(Stream (l[0], int(l[1],16), int(l[2],10), int(l[3],16), self.cmdData, self.type))
        return slst



def hasNumbers(inputString):
    return any(char.isdigit() for char in inputString)

def tsharkPath():
    cmd= 'which tshark'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        return line.rstrip()
    return ''
def get_tshark_version(p):
    cmd = p + ' -ver |grep -i tshark'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        lines = line.split(' ')
        for l in lines:
            if hasNumbers(l):
                print "tshark version: " + l
                v = l.split('.')
                if v[0] == '1' and v[1] < '12':
                    return "Your tshark version l is too old, minimum version is 1.12.0"
                elif v[0] == '2' and v[1] > '0': # new tshark use aaf fields
                    return "NEW"
                else: # old tshark use ieee1722a fields
                    return "OLD"
    return "tshark / wireshark version not found, please install one!"

def wtf(ss):
    for s in ss:
        #print s.cmd
        p = subprocess.Popen(s.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        fname = s.sid + '_' + format_info_vals[s.fmt] + '_' + str(s.chs) + \
                'ch_' +  sample_rate_type_vals[s.smr] + \
                ('.mpegts' if s.type == 'video' else '.raw')
        f = open(fname, 'wb')
        print 'write file: ' + fname
        for line in p.stdout.readlines():
            f.write(binascii.unhexlify(line))
        f.close()

if len(sys.argv) < 2:
    print "provide a pcap file"
    exit()

p=tsharkPath()
if len(p)==0:
    print "no wireshark/tshark installation found, please install one"

v = get_tshark_version(p)

aExt = AVBExtractor(sys.argv[1], 'audio', v, p)
vExt = AVBExtractor(sys.argv[1], 'video', v, p)
ss = aExt.get_streams()
ss = ss + vExt.get_streams()

print '----------------------- streams found ---------------------------'
for s in ss:
    print 'sid: ' + s.sid + ' fmt: ' + format_info_vals[s.fmt] + ' channels: ' + str(s.chs) + ' srate: ' + sample_rate_type_vals[s.smr]
print '----------------------- streams found ---------------------------'

wtf(ss)
