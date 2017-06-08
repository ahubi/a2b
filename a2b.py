# Date: 21.10.2016
import subprocess
import binascii
import socket
import sys
import re
import struct
import array

FORMAT_INFO_USER_SPECIFIED = 0
FORMAT_INFO_32FLOAT        = 1
FORMAT_INFO_32INTEGER      = 2
FORMAT_INFO_24INTEGER      = 3
FORMAT_INFO_16INTEGER      = 4

#key: (number of bytes as string, number of bits, python type code)
format_info ={
    FORMAT_INFO_USER_SPECIFIED:        ("User specified", 0, 'None'),
    FORMAT_INFO_32FLOAT:               ("32bit.f", 32, 'f'),
    FORMAT_INFO_32INTEGER:             ("32bit.i", 32, 'l'),
    FORMAT_INFO_24INTEGER:             ("24bit.i", 24, 'None'),
    FORMAT_INFO_16INTEGER:             ("16bit.i", 16, 'h'),
    0:                                 ("ts", 0, 'None')
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
#key: (sample rate as string, sample rate as number)
sample_rate = {
    SAMPLE_RATE_USER_SPECIFIED:        ("User specified", 0),
    SAMPLE_RATE_8K:                    ("8kHz", 8000),
    SAMPLE_RATE_16K:                   ("16kHz", 16000),
    SAMPLE_RATE_32K:                   ("32kHz", 32000),
    SAMPLE_RATE_44K1:                  ("44.1kHz",44100),
    SAMPLE_RATE_48K:                   ("48kHz", 48000),
    SAMPLE_RATE_88K2:                  ("88.2kHz", 882000),
    SAMPLE_RATE_96K:                   ("96kHz", 96000),
    SAMPLE_RATE_176K4:                 ("176.4kHz", 1764000),
    SAMPLE_RATE_192K:                  ("192kHz", 192000),
    SAMPLE_RATE_16RPM:                 ("24kHz", 24000),
    SAMPLE_RATE_33RPM3:                ("33 1-3 RPM", 33000), # not sure this is correct number
    SAMPLE_RATE_33RPM3_REV:            ("33 1-3 RPM In Reverse", 330000),
    SAMPLE_RATE_45RPM:                 ("45RPM", 45000),
    SAMPLE_RATE_78RPM:                 ("78RPM", 45000),
    SAMPLE_RATE_RESERVED:              ("Reserved", 0),
    0:                                 ("mpeg", 0)
}

class Stream(object):
    def __init__(self, sid=None, fmt=None, chs=None, smr=None, cmd=None, type=None, stime=None):
        self.sid  = sid    # stream id
        self.fmt  = fmt    # format 16bit
        self.chs  = chs    # number of channels
        self.smr  = smr    # sample rate
        self.cmd  = cmd    # command for extracting payload data from stream
        self.type = type   # stream type, a = audio, v = video tv / ts stream
        self.stime = stime   # frma.time of first occurence

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
            self.cmdStreams.insert(0,TsCmd + file + ' -T fields' + strFds + ' -e frame.time')
            self.cmdData = TsCmd + file + ' -T fields -e ' + pref + 'data ' + pref + 'stream_id == '
        elif type == 'video':
            pref = 'ieee1722.'
            for f in vfds:
                strFds = strFds + ' -e ' + pref + f
            self.cmdStreams.insert(0,TsCmd + file + ' -T fields' + strFds + ' -e frame.time ' + pref + 'subtype == 0x00')
            self.cmdData = TsCmd + file + ' -T fields -e ' + pref + 'data ' + pref + 'subtype == 0x00 and ' + pref + 'stream_id == '

    def get_streams(self):
        slst = []
        for cmd in self.cmdStreams:
            #print cmd
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                l = line.split('\t')
                if len(l) == 5:
                    if len(l[0])>0:
                        found = 0
                        for stream in slst:
                            if l[0] in stream.sid:
                                found = 1
                                break;
                        if found == 0:
                            cmdData = self.cmdData + l[0]
                            if self.type == 'video': # todo remove this ugly hack
                                slst.append(Stream (l[0], 0, 0, 0, cmdData, self.type, l[4].rstrip()))
                            else:
                                slst.append(Stream (l[0], int(l[1],16), int(l[2],10), int(l[3],16), cmdData, self.type, l[4].rstrip()))
        return slst

def hasNumbers(inputString):
    return any(char.isdigit() for char in inputString)

def tsharkPath():
    cmd= 'which tshark'
    if sys.platform=="win32":
        cmd= 'where tshark'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        if len(line)>0:
            return '"' + line.rstrip() + '"'
    return None

def get_tshark_version(p):
    cmd = p + ' -ver |grep -i tshark'
    if sys.platform == "win32":
        cmd =p + ' -ver |findstr -i tshark'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        lines = line.split(' ')
        for l in lines:
            #print l
            if hasNumbers(l):
                print "tshark version: " + l
                v = l.split('.')
                if v[0] == '1' and v[1] < '12':
                    return "Your tshark version l is too old, minimum version is 1.12.0"
                elif v[0] == '2' and v[1] > '0': # new tshark use aaf fields
                    return "NEW"
                else: # old tshark use ieee1722a fields
                    return "OLD"
    return "tshark / wireshark version not matching, check your wireshark version!"

def hexstring_to_bytes(hex_string):
    res = ""
    for i in range(0, len(hex_string), 2):
        res += chr(int(hex_string[i:i+2], 16))
    return res
# see http://soundfile.sapp.org/doc/WaveFormat/
def write_wav_header(f, data_len, chs, samplerate, bits_per_sample, fmt=1):
    f.seek(0, 0)
    f.write("RIFF")
    f.write(struct.pack('<L', 36 + data_len))
    f.write("WAVEfmt ")
    f.write(struct.pack('<L', 16))
    f.write(struct.pack('<H', fmt))
    f.write(struct.pack('<H', chs))
    f.write(struct.pack('<L', samplerate))
    f.write(struct.pack('<L', samplerate * chs * bits_per_sample / 8))
    f.write(struct.pack('<H', chs * bits_per_sample / 8))
    f.write(struct.pack('<H', bits_per_sample))
    f.write("data")
    f.write(struct.pack('<L', data_len))

#x - data, t - type('h')
def swap_bytes(x, t):
    if t=='None':
        return x
    else:
        y = array.array(t, x)
        y.byteswap()
        return y

def wtf(ss):
    for s in ss:
        #print s.cmd
        nbytes = 0
        p = subprocess.Popen(s.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        fname = s.sid + '_' + s.stime.translate(None, ',: ') + \
                format_info[s.fmt][0] + '_' + str(s.chs) + 'ch_' + \
                sample_rate[s.smr][0] + \
                ('.mpegts' if s.type == 'video' else '.wav')
        f = open(fname, 'wb')
        print 'wtf: ' + fname
        for line in p.stdout.readlines():
            line = line.rstrip()
            line = line.lstrip()
            line = line.replace(":","")
            #swap bytes necessary due to big endian on network, but little endian in WAVE format
            f.write(swap_bytes(binascii.unhexlify(line), format_info[s.fmt][2]))
            nbytes += len(line)
        if s.type=='audio':
            write_wav_header(f, nbytes, s.chs,
                            sample_rate[s.smr][1],
                            format_info[s.fmt][1])
        f.close()

if len(sys.argv) < 2:
    print "provide a pcap file"
    exit()

p=tsharkPath()
#print p
if p==None:
    print "no wireshark/tshark installation found, please install one"
    exit()

v = get_tshark_version(p)
if v=='OLD' or v=='NEW':
    aExt = AVBExtractor(sys.argv[1], 'audio', v, p)
    vExt = AVBExtractor(sys.argv[1], 'video', v, p)
    ss = aExt.get_streams()
    ss = ss + vExt.get_streams()

    print '----------------------- streams found ---------------------------'
    for s in ss:
        print 'sid: ' + s.sid + ' ' + format_info[s.fmt][0] + \
        ',' + str(s.chs) + ',' + sample_rate[s.smr][0] + \
        ' ' + s.stime
    print '----------------------- streams found ---------------------------'
    wtf(ss)
else:
    print v
