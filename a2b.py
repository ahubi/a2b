# author: Artur Hubert
# Date: 21.10.2016
import subprocess
import binascii
import socket
import sys
import re

cmdVer = 'tshark -ver |grep -i tshark'

class Stream(object):
    def __init__(self, sid=None, fmt=None, chs=None, smr=None, cmd=None, type=None):
        self.sid  = sid    # stream id
        self.fmt  = fmt    # format 16bit
        self.chs  = chs    # number of channels
        self.smr  = smr    # sample rate
        self.cmd  = cmd    # command for extracting payload data from stream
        self.type = type   # stream type, a = audio, v = video tv / ts stream

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
    0:                                 "NULL"
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
    0:                                 "NULL"
}

def hasNumbers(inputString):
    return any(char.isdigit() for char in inputString)

def get_tshark_version(cmd):
    print cmd
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

def get_streams(cmds, v):
    slst = []
    for cmd in cmds:
        print cmd
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
                        if v == "NEW":
                            if('ieee1722.subtype' in cmd): # video stream
                                cmdData = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722.data ieee1722.subtype == 0x00 and ieee1722.stream_id == ' + l[0] + ' | tr -d \'\\n\\t\\r:, \''
                                slst.append(Stream (l[0], 0, 0, 0, cmdData, 'v'))
                            else:
                                cmdData = 'tshark -r ' + sys.argv[1] + ' -T fields -e aaf.data.sample aaf.stream_id == ' + l[0] + ' | tr -d \'\\n\\t\\r:, \''
                                slst.append(Stream (l[0], int(l[1],16), int(l[2],10), int(l[3],16), cmdData, 'a'))
                        elif v == "OLD":
                            if('ieee1722.subtype' in cmd): # video stream
                                cmdData = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722.data ieee1722.subtype == 0x00 and ieee1722.stream_id == ' + l[0] + ' | tr -d \'\\n\\t\\r:, \''
                                slst.append(Stream (l[0], 0, 0, 0, cmdData, 'v'))
                            else:
                                cmdData = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722a.data.sample.sampledata ieee1722a.stream_id == ' + l[0] + ' | tr -d \'\\n\\t\\r:, \''
                                slst.append(Stream (l[0], int(l[1],16), int(l[2],10), int(l[3],16), cmdData, 'a'))

    return slst

def wtf(ss, v):
    for s in ss:
        print s.cmd
        p = subprocess.Popen(s.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        fname = s.sid + '_' + format_info_vals[s.fmt] + '_' + str(s.chs) + \
                'ch_' +  sample_rate_type_vals[s.smr] + \
                ('.ts' if s.type == 'v' else '.raw')
        f = open(fname, 'wb')
        print 'write file: ' + fname
        for line in p.stdout.readlines():
            f.write(binascii.unhexlify(line))
        f.close()

if len(sys.argv) < 2:
    print "provide a pcap file"
    exit()

v = get_tshark_version(cmdVer)
cmdStreams = []
if v == "OLD":
    audio = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722a.stream_id -e ieee1722a.format_info -e ieee1722a.channels_per_frame -e ieee1722a.nominal_sample_rate'
    video = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722.stream_id -e ieee1722.fmt -e ieee1722.subtype -e ieee1722.verfield ieee1722.subtype == 0x00'
    cmdStreams.insert(0, audio)
    cmdStreams.insert(1, video)
elif v == "NEW":
    audio = 'tshark -r ' + sys.argv[1] + ' -T fields -e aaf.stream_id -e aaf.format_info -e aaf.channels_per_frame -e aaf.nominal_sample_rate'
    video = 'tshark -r ' + sys.argv[1] + ' -T fields -e ieee1722.stream_id -e ieee1722.fmt -e ieee1722.subtype -e ieee1722.verfield ieee1722.subtype == 0x00'
    cmdStreams.insert(0, audio)
    cmdStreams.insert(1, video)
else:
    print v
    exit()

ss = get_streams(cmdStreams,v)

print '----------------------- Streams found ---------------------------'
for s in ss:
    print 'sid: ' + s.sid + ' fmt: ' + format_info_vals[s.fmt] + ' channels: ' + str(s.chs) + ' srate: ' + sample_rate_type_vals[s.smr]

print '----------------------- Streams found ---------------------------'
wtf(ss,v)
