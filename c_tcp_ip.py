#!/usr/bin/python
"""
Created on Mon Jul  7 14:23:44 2024

@author: anwar.thoyib@gmail.com
"""

import struct
import codecs

##############################################################################
class Line:
  DEBUG           = False
  _Line           = ''
  _PayLoad        = ''
#  _PayLoadSegment = False
  _HeaderSegment  = False
  _HeaderCounter  = 0
  _ByteCounter    = 0
  utf8encoder     = codecs.getencoder("utf_8")
  utf8decoder     = codecs.getdecoder("utf_8")

  def __init__(self):
    self.EOF = False

  def setDebug(self, myst):
    self.DEBUG = myst

  def setLine(self, myStr):
    self._Line = myStr

  def chopLine(self, size):
#    print("--> " + str(len(self._Line)) + " " + str(size))
    tmp        = self._Line[0:size]
    self._Line = self._Line[size:]
    if not self._Line: self.EOF = True

    return tmp

  def chopPayLoad(self, size):
#    print("==> " + str(len(self._PayLoad)) + " " + str(size))
    tmp           = self._PayLoad[0:size]
    self._PayLoad = self._PayLoad[size:]
#    if not self._PayLoad : self._PayLoadSegment = False

    if self._HeaderSegment: self._HeaderCounter += size
    else                  : self._ByteCounter   += size

    return tmp

  def _chopinteger(self, size):
    chop_int_hex       = self.chopPayLoad(size)
    chop_int           = int(chop_int_hex, 16)
    self._ByteCounter += size
    return chop_int_hex, chop_int

  def decode_UTF8String(self, data):
    return data.decode("hex")

  def decode_Unsigned32(self, data):
    return int(data, 16)

  def decode_Integer32(self, data):
#    return data.decode("hex")
    return int(data, 16)

  def decode_Time(self, data):
    seconds_between_1900_and_1970 = ((70 * 365) + 17) * 86400
    ret = struct.unpack("!I", data.decode("hex"))[0]
    return int(ret) - seconds_between_1900_and_1970

  def showInfo(self, myStr):
    if self.DEBUG: print(myStr)

  def getPayLoad(self):
    return self._PayLoad


##############################################################################
class Frame(Line):
  __FirstFrame = True
  __counter = 0

  def __init__(self):
    Line.__init__(self)
    self._FrameLength    = 100000
    self._FrameTimeStamp = ''
    self._CaptureLength  = 100000
    self.FrameHeader     = ''
    self.FrameTrailer    = ''

  def _reset(self):
    self._PayLoad        = ''
    self._FrameLength    = 100000
    self._FrameTimeStamp = ''
    self._CaptureLength  = 100000
    self.FrameHeader     = ''
    self.FrameTrailer    = ''

  def collectFrameHeader(self):
    self.__counter += 1
    self.showInfo("===" + str(self.__counter) + "===============================================================")
    self.showInfo("--- Frame Ethernet -----------------------------------------------")
    self._reset()
    if self.__FirstFrame:  # 16 + 8 = 24 byte
      frame_header1_hex = self.chopLine(32)
      frame_header2_hex = self.chopLine(16)
      self.showInfo(frame_header1_hex + " Frame Header")
      self.showInfo(frame_header2_hex)
      self.FrameHeader += frame_header1_hex
      self.FrameHeader += frame_header2_hex
      self._FrameTimeStamp = self.FrameHeader
      self.__FirstFrame = False

    # 8 + 4 + 4 = 16 byte
    # 0A 00 1F 88
    frame_header3_hex = self.chopLine(16)
    frame_header4_hex = self.chopLine(8)
    frame_header5_hex = self.chopLine(8)
    self.showInfo(frame_header3_hex)
    self.showInfo(frame_header4_hex)
    self.showInfo(frame_header5_hex)
    self.FrameHeader += frame_header3_hex
    self.FrameHeader += frame_header4_hex
    self.FrameHeader += frame_header5_hex
    FrameLength   = frame_header4_hex[6:8] + frame_header4_hex[4:6] + frame_header4_hex[2:4] + frame_header4_hex[0:2]
    CaptureLength = frame_header5_hex[6:8] + frame_header5_hex[4:6] + frame_header5_hex[2:4] + frame_header5_hex[0:2]
    self._FrameLength   = int(FrameLength, 16)
    self._CaptureLength = int(CaptureLength, 16)
    self.showInfo("Frame Length:   " + FrameLength   + " | " + str(self._FrameLength))
    self.showInfo("Capture Length: " + CaptureLength + " | " + str(self._CaptureLength))
    return True

# FrameHeader|PayLoad|FrameTrailer
# .....Length|

  def collectPayLoad(self):
#    self._PayLoad = self.chopLine((self._FrameLength * 2) - 268)
    self._PayLoad = self.chopLine(self._FrameLength * 2)
#    print(self._PayLoad)
#    if self._PayLoad:
#      self._PayLoadSegment = True

  def collectFrameTrailer(self): #268
    frame_trailer1_hex = self.chopLine(32)
    frame_trailer2_hex = self.chopLine(32)
    frame_trailer3_hex = self.chopLine(32)
    frame_trailer4_hex = self.chopLine(32)
    frame_trailer5_hex = self.chopLine(32)
    frame_trailer6_hex = self.chopLine(32)
    frame_trailer7_hex = self.chopLine(32)
    frame_trailer8_hex = self.chopLine(32)
    frame_trailer9_hex = self.chopLine(12)
    self.showInfo(frame_trailer1_hex + " Frame Trailer")
    self.showInfo(frame_trailer2_hex)
    self.showInfo(frame_trailer3_hex)
    self.showInfo(frame_trailer4_hex)
    self.showInfo(frame_trailer5_hex)
    self.showInfo(frame_trailer6_hex)
    self.showInfo(frame_trailer7_hex)
    self.showInfo(frame_trailer8_hex)
    self.showInfo(frame_trailer9_hex)
    self.FrameTrailer += frame_trailer1_hex
    self.FrameTrailer += frame_trailer2_hex
    self.FrameTrailer += frame_trailer3_hex
    self.FrameTrailer += frame_trailer4_hex
    self.FrameTrailer += frame_trailer5_hex
    self.FrameTrailer += frame_trailer6_hex
    self.FrameTrailer += frame_trailer7_hex
    self.FrameTrailer += frame_trailer8_hex
    self.FrameTrailer += frame_trailer9_hex
    return True

  def collectFrame(self):
    self.collectFrameHeader()
    self.collectPayLoad()
    #self.collectFrameTrailer()



##############################################################################
#Header|PayLoad
#Header:   _MACAddressDst
class Ethernet(Frame):

  def __init__(self):
    Frame.__init__(self)
    self.Ethernet                        = dict()
    self.Ethernet['address_destination'] = '00:00:00:00:00:00'
    self.Ethernet['address_source']      = '00:00:00:00:00:00'

  def showMacAddr(self, myStr):
    return myStr[0:2] + ":" + myStr[2:4] + ":" + myStr[4:6] + ":" + myStr[6:8] + ":" + myStr[8:10] + ":" + myStr[10:12]

  def __getMacAddress(self):
    eth_mac_addr_hex = self.chopPayLoad(12)
    eth_mac_addr   = self.showMacAddr(eth_mac_addr_hex)
    return eth_mac_addr_hex, eth_mac_addr

  def __getMacAddressDst(self):
    eth_mac_addr_dst_hex, self.Ethernet['address_destination'] = self.__getMacAddress()
    self.showInfo(eth_mac_addr_dst_hex + "\t Mac Address Destination: " + self.Ethernet['address_destination'])

  def __getMacAddressSrc(self):
    eth_mac_addr_src_hex, self.Ethernet['address_source']  = self.__getMacAddress()
    self.showInfo(eth_mac_addr_src_hex + "\t Mac Address Source: " + self.Ethernet['address_source'])

  def __getVersion(self):
    eth_ip_version_hex = self.chopPayLoad(4)
    eth_ip_version     = ''
    if eth_ip_version_hex == '0800':
      eth_ip_version = 'IPv4'
      self.showInfo(eth_ip_version_hex + "\t\t IP Version: " + eth_ip_version)

  def collectEthernet(self):
    self.Ethernet = dict()
    self.showInfo("--- Ethernet ----------------------------------------------------")
    self.__getMacAddressDst()
    self.__getMacAddressSrc()
    if self.Ethernet['address_destination'] == '00:00:00:00:00:00' and self._MACAddressSrc == '00:00:00:00:00:00':
      self.EOF = True
      print("!!!Error: package truncated!")
      exit(0)

    self.__getVersion()
    return True



##############################################################################
class IP(Ethernet):
  _currIPSize = 0

  def __init__(self):
    Ethernet.__init__(self)
    self.IP = dict()

  def __reset(self):
    self.IP             = dict()
    self._HeaderSegment = True
    self._HeaderCounter = 0
    self._currIPSize = 0

  def chopIPPayLoad(self, size):
#    print("==> " + str(len(self._PayLoad)) + " " + str(size))
    self._currIPSize += size
    tmp           = self._PayLoad[0:size]
    self._PayLoad = self._PayLoad[size:]
#    if not self._PayLoad : self._PayLoadSegment = False

    if self._HeaderSegment: self._HeaderCounter += size
    else                  : self._ByteCounter   += size

    return tmp

  def _chopIPinteger(self, size):
    chop_int_hex       = self.chopIPPayLoad(size)
    chop_int           = int(chop_int_hex, 16)
    self._ByteCounter += size
    return chop_int_hex, chop_int

  def showIPAddr(self, myStr):
    return str(int(myStr[0:2], 16)) + "." + str(int(myStr[2:4], 16)) + "." + str(int(myStr[4:6], 16)) + "." + str(int(myStr[6:8], 16))

  def __getVersion(self):
    ip_version_hex, self.IP['version'] = self._chopIPinteger(1)
    self.showInfo(ip_version_hex + "\t\t IP Version: " + ip_version_hex)

  def __getHeaderLength(self):
    ip_header_length_hex, ip_header_length = self._chopIPinteger(1)
    self.IP['header_length'] = ip_header_length * 4
    self.showInfo(ip_header_length_hex + "\t\t Header Length: " + str(self.IP['header_length']))

  def __getIPDifferentiatedService(self):
    ip_differentiated_service_hex     = self.chopIPPayLoad(2)
    self.IP['differentiated_service'] = ip_differentiated_service_hex
    self.showInfo(ip_differentiated_service_hex + "\t\t Differentiated Service Field: " + ip_differentiated_service_hex)

  def __getTotalLength(self):
    ip_total_length_hex, self.IP['total_length'] = self._chopIPinteger(4)
    self.showInfo(ip_total_length_hex + "\t\t Total Length: " + str(self.IP['total_length']))

  def __getIdentification(self):
    ip_identification_hex, self.IP['identification'] = self._chopIPinteger(4)
    self.showInfo(ip_identification_hex + "\t\t Identification : " + str(self.IP['identification']))

  def __getFlag(self):
    ip_flags_hex   = self.chopIPPayLoad(2)
    self.IP['flags'] = ip_flags_hex
    self.showInfo(ip_flags_hex + "\t\t Flag: " + self.IP['flags'])

  def __getFragmentOffset(self):
    ip_fragment_offset_hex, self.IP['fragment_offset'] = self._chopIPinteger(2)
    self.showInfo(ip_fragment_offset_hex + "\t\t Fragment Offset: " + str(self.IP['fragment_offset']))

  def __getTimetoLive(self):
    ip_time_to_live_hex, self.IP['time_to_live'] = self._chopIPinteger(2)
    self.showInfo(ip_time_to_live_hex + "\t\t Time to Live: " + str(self.IP['time_to_live']))

  def __getProtocol(self):
    ip_protocol_hex = self.chopIPPayLoad(2)
    ip_protocol      = ''
    if ip_protocol_hex == '06':  ip_protocol = 'TCP'

    self.IP['protocol'] = ip_protocol
    self.showInfo(ip_protocol_hex + "\t\t Protocol: " + ip_protocol)

  def __getHeaderChecksum(self):
    ip_header_checksum_hex = self.chopIPPayLoad(4)
    self.showInfo(ip_header_checksum_hex + "\t\t Header Checksum: " + ip_header_checksum_hex)

  def __getIPAddress(self):
    ip_addr_hex = self.chopIPPayLoad(8)
    ip_addr      = self.showIPAddr(ip_addr_hex)
    return ip_addr_hex, ip_addr

  def __getIPAddressSrc(self):
    ip_addr_src_hex, self.IP['address_source'] = self.__getIPAddress()
    self.showInfo(ip_addr_src_hex + "\t IP Address Src: " + self.IP['address_source'])

  def __getIPAddressDst(self):
    ip_addr_dst_hex, self.IP['address_destination'] = self.__getIPAddress()
    self.showInfo(ip_addr_dst_hex + "\t IP Address Dst: " + self.IP['address_destination'])

  def __getUrgentPointer(self):
    size = (self.IP['header_length'] * 2) - self._HeaderCounter
    if size > 0:
      ip_urgent_pointer_hex = self.chopIPPayLoad(size)
      self.showInfo(ip_urgent_pointer_hex + "\t\t Urgent Pointer: " + ip_urgent_pointer_hex)
    else:
      self._HeaderSegment = False

  def collectIP(self):
    self.__reset()
    self.showInfo("--- IP ----------------------------------------------------------")
    self.__getVersion()
    self.__getHeaderLength()
    self.__getIPDifferentiatedService()
    self.__getTotalLength()
    self.__getIdentification()
    self.__getFlag()
    self.__getFragmentOffset()
    self.__getTimetoLive()
    self.__getProtocol()
    self.__getHeaderChecksum()
    self.__getIPAddressSrc()
    self.__getIPAddressDst()
    self.__getUrgentPointer()



##############################################################################
class TCP(IP):

  def __init__(self):
    IP.__init__(self)
    self.TCP = dict()

  def __reset(self):
    self.TCP      = dict()
    self._HeaderSegment = True
    self._HeaderCounter = 0

  def __getPortSrc(self):
    tcp_port_src_hex, self.TCP['port_source'] = self._chopIPinteger(4)
    self.showInfo(tcp_port_src_hex + "\t\t Port Src: " + str(self.TCP['port_source']))

  def __getPortDst(self):
    tcp_port_dst_hex, self.TCP['port_destination'] = self._chopIPinteger(4)
    self.showInfo(tcp_port_dst_hex + "\t\t Port Dst: " + str(self.TCP['port_destination']))

  def __getStreamIndexLength(self):
    tcp_stream_index_length_hex    = self.chopIPPayLoad(16)
    self.TCP['stream_index_lengt'] = tcp_stream_index_length_hex
    self.showInfo(tcp_stream_index_length_hex + " stream index, tcp length")

  def __getHeaderLength(self):
    tcp_header_length_hex, tcp_header_length = self._chopIPinteger(1)
    self.TCP['header_length']                = tcp_header_length * 4
    self.showInfo(tcp_header_length_hex + "\t\t Header Length: " + str(self.TCP['header_length']))

  def __getFlags(self):
    tcp_flags_hex     = self.chopIPPayLoad(3)
    self.TCP['flags'] = int(tcp_flags_hex)
    self.showInfo(tcp_flags_hex + "\t\t Flag: " + str(tcp_flags_hex))

  def __getWindowsSize(self):
    tcp_windows_size_hex, self.TCP['windows_size'] = self._chopIPinteger(4)
    self.showInfo(tcp_windows_size_hex + "\t\t Windows Size: " + str(self.TCP['windows_size']))

  def __getChecksum(self):
    tcp_checksum_hex         = self.chopIPPayLoad(4)
    self.TCP['checksum_hex'] = tcp_checksum_hex
    self.showInfo(tcp_checksum_hex + "\t\t Checksum: " + tcp_checksum_hex)

  def __getUrgentPointer(self):
    tcp_urgent_pointer_hex = self.chopIPPayLoad(4)
    self.showInfo(tcp_urgent_pointer_hex + "\t\t Urgent Pointer: " + tcp_urgent_pointer_hex)

  def __getTCPOptions(self):
#    print("==> tcp_header_length: " + str(self.TCP['header_length']))
    tcp_option_length = self.TCP['header_length'] - 20
#    print("==> tcp_option_length: " + str(tcp_option_length))
    tcp_option_hex = self.chopIPPayLoad(tcp_option_length * 2)
#    print(tcp_option_hex[0:16] + " Options: " + tcp_option_hex)
#    print(tcp_option_hex[16 :32])


  def collectTCP(self):
    self.__reset()
    self.showInfo("--- TCP ---------------------------------------------------------")
    self.__getPortSrc()
    self.__getPortDst()
    self.__getStreamIndexLength()
    self.__getHeaderLength()
    self.__getFlags()
    self.__getWindowsSize()
    self.__getChecksum()
    self.__getUrgentPointer()
    if self.TCP['header_length'] > 20:
      self.__getTCPOptions()
#    print("==> currIPSize: " + str(self._currIPSize))
#    print("==> PayLoad: " + str(len(self._PayLoad)))
#    footer = (self.IP['total_length'] * 2) - self._currIPSize
#    print("==> footer: " + str(footer))


