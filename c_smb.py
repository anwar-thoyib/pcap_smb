#!/usr/bin/python
"""
Created on Mon Jul  7 14:25:05 2024

@author: anwar.thoyib@gmail.com
"""

import xml.dom.minidom as minidom
import datetime
import os
import re
import json
#import pytz
from collections import OrderedDict

from c_tcpip import IP
from c_tcpip import TCP

##############################################################################
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                            Length                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                            Offset                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  WriteChannelInfoOffset       |   WriteChannelInfoLength      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                            Flags                              |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                            Buffer                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class NetBIOS(TCP):

  def __init__(self):
    TCP.__init__(self)
    self.NetBIOS = dict()

  def __getMessageType(self):
    message_type_hex = self.chopPayLoad(2)
    self.NetBIOS['message_type'] = message_type_hex
    self.showInfo(message_type_hex +"               Message Type: "+ message_type_hex)

  def __getLength(self):
    length_hex, self.NetBIOS['length'] = self._chopinteger(6)
#    self.NetBIOS['length'] = length_hex
    self.showInfo(length_hex +"           Length: "+ str(self.NetBIOS['length']))

  def collectNetBIOS(self):
    self.showInfo("--- NetBIOS ---------------------------------------------------------")
    self.__getMessageType()
    self.__getLength()
    self._HeaderSegment = False
    self._ByteCounter   = 0



##############################################################################
class SMB(NetBIOS):
  def __init__(self):
    NetBIOS.__init__(self)
    self.SMB                           = dict()
    self.SMB['length']                 = 50000
    self._AVP_List                          = []
    self._Filter_MACAddressDestination      = ''
    self._Filter_MACAddressSource           = ''
    self._Filter_IPAddressSource            = ''
    self._Filter_IPAddressDestination       = ''
    self._Filter_PortSource                 = 0
    self._Filter_PortDestination            = 0
    self._Filter_AVP                        = dict()
    self._Output_MACAddressDestination      = False
    self._Output_MACAddressSource           = False
    self._Output_IPAddressSource            = False
    self._Output_IPAddressDestination       = False
    self._Output_PortSource                 = False
    self._Output_PortDestination            = False
    self._Output_SMBCommandCode             = False
    self._Output_SMBRequest                 = False
    self._Output_SMBApplicationId           = False

    self._TextOutput                        = ''
    self.__readConfig('smb.cfg')

    self.result = OrderedDict([('filename', ''),               \
                               ('file_size', ''),              \
                               ('ip_address_source', ''),      \
                               ('port_source', ''),            \
                               ('ip_address_destination', ''), \
                               ('port_destination', ''),       \
                               ('timestamp', ''),              \
                               ('date_time', '')])

  def _reset(self):
    self.SMB           = dict()
    self.SMB['length'] = 50000
    self._TextOutput        = ''
    del self._AVP_List[:]

  def __readParamBool(self, myvalue):
    value = myvalue.upper()
    if value in ('TRUE' , 'YES', 'ON' , 'Y'): return True
    if value in ('FALSE', 'NO' , 'OFF', 'N'): return False

  def __readConfig(self, myfile):
    if not os.path.isfile(myfile):
      print("ERROR: Config file \"" + myfile + "\" not exist!")
      exit(0)

    ConfigSegment = ''

    configfile = open(myfile)
    for line in configfile.readlines():
      q_line = re.search("^\[(\w+)\]", line)
      if q_line:
        ConfigSegment = q_line.group(1).upper()
        continue

      if ConfigSegment == 'FILTER':
        q_line = re.search("^MAC_Address_Destination\s*=\s*(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})", line)
        if q_line:
          self._Filter_MACAddressDestination = q_line.group(1)
          continue

        q_line = re.search("^MAC_Address_Source\s*=\s*(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})", line)
        if q_line:
          self._Filter_MACAddressSource = q_line.group(1)
          continue

        q_line = re.search("^IP_Address_Source\s*=\s*(\d+\.\d+\.\d+\.\d+)", line)
        if q_line:
          self._Filter_IPAddressSource = q_line.group(1)
          continue

        q_line = re.search("^IP_Address_Destination\s*=\s*(\d+\.\d+\.\d+\.\d+)", line)
        if q_line:
          self._Filter_IPAddressDestination = q_line.group(1)
          continue

        q_line = re.search("^Port_Source\s*=\s*(\d+)", line)
        if q_line:
          self._Filter_PortSource = q_line.group(1)
          continue

        q_line = re.search("^Port_Destination\s*=\s*(\d+)", line)
        if q_line:
          self._Filter_PortDestination = q_line.group(1)
          continue

      if ConfigSegment == 'OUTPUT':
        q_line = re.search("^MAC_Address_Destination\s*=\s*(\w+)", line)
        if q_line:
          self._Output_MACAddressDestination = self.__readParamBool(q_line.group(1))
          continue

        q_line = re.search("^MAC_Address_Source\s*=\s*(\w+)", line)
        if q_line:
          self._Output_MACAddressSource = self.__readParamBool(q_line.group(1))
          continue

        q_line = re.search("^IP_Address_Source\s*=\s*(\w+)", line)
        if q_line:
          self._Output_IPAddressSource = self.__readParamBool(q_line.group(1))
          continue

        q_line = re.search("^IP_Address_Destination\s*=\s*(\w+)", line)
        if q_line:
          self._Output_IPAddressDestination = self.__readParamBool(q_line.group(1))
          continue

        q_line = re.search("^Port_Source\s*=\s*(\w+)", line)
        if q_line:
          self._Output_PortSource = self.__readParamBool(q_line.group(1))
          continue

        q_line = re.search("^Port_Destination\s*=\s*(\w+)", line)
        if q_line:
          self._Output_PortDestination = self.__readParamBool(q_line.group(1))
          continue

    configfile.close()


  def _showBit(self, flags, bit, msg):
    hex_num_set = (0, 128, 64, 32, 16, 8, 4, 2, 1)
    msg += ': '
    tmp = ''
    for index, hex_num in enumerate(hex_num_set):
      if index:
        if index == bit:
          if flags & hex_num == hex_num:
            tmp += '1'
          else:
            tmp += '0'
            msg += 'Not '
        else:
          tmp += '.'

        if index == 4:
          tmp += ' '

    tmp += ' = ' + msg + 'Set'
    return tmp


  def __getCommandCode(self):
    smb_command_code_hex, self.SMB['command_code'] = self._chopinteger(6)
    tmp = smb_command_code_hex + "\t\t Command Code: "
    tmp += str(self.dictcommands2name(self.SMB['command_code']))
    tmp += '(' + str(self.SMB['command_code']) + ')'
    self.showInfo(tmp)

  def __getApplicationId(self):
    smb_application_id_hex, self.SMB['application_id'] = self._chopinteger(8)
    self.showInfo(smb_application_id_hex + "\t ApplicationId: " + str(self.SMB['application_id']))

  def __getHopbyHopIdentifier(self):
    smb_hop_by_hop_ident_hex                  = self.chopPayLoad(8)
    self.SMB['hop_by_hop_idententifier'] = smb_hop_by_hop_ident_hex
    self.showInfo(smb_hop_by_hop_ident_hex + "\t Hop by Hop Identifier: " + self.SMB['hop_by_hop_idententifier'])

  def __getEndtoEndIdentifier(self):
    smb_end_to_end_ident_hex = self.chopPayLoad(8)
    self.SMB['end_to_end_idententifier'] = smb_end_to_end_ident_hex
    self.showInfo(smb_end_to_end_ident_hex + "\t End to End Identifier: " + self.SMB['end_to_end_idententifier'])

### FILTERING ################################################################
  def __checkFilter_MACAddressDestination(self):
    if self._Filter_MACAddressDestination != '':
      if self._Filter_MACAddressDestination != self.Ethernet['address_destination']:
        return False
    return True

  def __checkFilter_MACAddressSource(self):
    if self._Filter_MACAddressSource != '':
      if self._Filter_MACAddressSource != self.Ethernet['address_source']:
        return False
    return True

  def __checkFilter_IPAddressSource(self):
    if self._Filter_IPAddressSource != '':
      if self._Filter_IPAddressSource != self.IP['address_source']:
        return False
    return True

  def __checkFilter_IPAddressDestination(self):
    if self._Filter_IPAddressDestination != '':
      if self._Filter_IPAddressDestination != self.IP['address_destination']:
        return False
    return True

  def __checkFilter_PortSource(self):
    if int(self._Filter_PortSource) > 0:
      if int(self._Filter_PortSource) != int(self.TCP['port_source']):
        return False
    return True

  def __checkFilter_PortDestination(self):
    if int(self._Filter_PortDestination) > 0:
      if int(self._Filter_PortDestination) != int(self.TCP['port_destination']):
        return False
    return True

  def __checkFilter_SMBRequest(self):
    if self._Filter_DiameterRequest != '':
      if bool(self._Filter_DiameterRequest) != self.SMB['request']:
        return False
    return True

  def __checkFilter_SMBCommandCode(self):
    if self._Filter_DiameterCommandCode:
      if int(self._Filter_DiameterCommandCode) != int(self.SMB['command_code']):
        return False
    return True

  def __checkFilter_DiameterApplicationId(self):
    if self._Filter_DiameterApplicationId:
      if int(self._Filter_DiameterApplicationId) != int(self.Diameter['application_id']):
        return False
    return True

  def __checkFilter_DiameterHopbyHopIdentifier(self):
    if self._Filter_DiameterHopbyHopIdentifier:
      if int(self._Filter_DiameterHopbyHopIdentifier) != int(self.SMB['hop_by_hop_idententifier']):
        return False
    return True

  def __checkFilter_DiameterEndtoEndIdentifier(self):
    if self._Filter_DiameterEndtoEndIdentifier:
      if int(self._Filter_DiameterEndtoEndIdentifier) != int(self.SMB['end_to_end_idententifier']):
        return False
    return True

  def __checkFilter_AVP(self):
    if self._Filter_AVP:
      for myid in self._Filter_AVP:
        if self._Filter_AVP[myid]:
          self._Filter_AVP[myid] = False

      for myAVP in self._AVP_List:
        myid = str(myAVP['id'])
        if myid in self._Filter_AVP:
          self._Filter_AVP[myid] = True

      for myid in self._Filter_AVP:
        if not self._Filter_AVP[myid]:
          return False

    return True

  def __getProtocolId(self):
    protocol_id_hex = self.chopPayLoad(8)
    self.showInfo(protocol_id_hex +"         ProtocolId: "+ protocol_id_hex)
    self.SMB['protocol_id'] = protocol_id_hex

  def __getHeaderLength(self):
    tmp = self.chopPayLoad(4)
    header_length_hex = tmp[2:4] + tmp[0:2]
    self.SMB['header_length'] = int(header_length_hex, 16)
    self.showInfo(tmp +"             Header Length: "+ str(self.SMB['header_length']))

  def __getCreditCharge(self):
    tmp = self.chopPayLoad(4)
    credit_charge_hex = tmp[2:4] + tmp[0:2]
    self.SMB['credit_charge'] = credit_charge_hex
    self.showInfo(tmp +"             Credit Charge: "+ str(self.SMB['credit_charge']))

  def __getChannelSequence(self):
    channel_squence_hex = self.chopPayLoad(4)
    self.SMB['channel_sequence'] = channel_squence_hex
    self.showInfo(channel_squence_hex +"             Channel Sequence: "+ str(self.SMB['channel_sequence']))

  def __reserved(self, size):
    reserved_hex = self.chopPayLoad(size)
    self.showInfo(reserved_hex +"  Reserved: "+ reserved_hex)

  def __getCommand(self):
    tmp = self.chopPayLoad(4)
    command_hex = tmp[2:4] + tmp[0:2]
    self.SMB['command_code'] = command_hex
    self.showInfo(tmp +"             Command: "+ str(self.SMB['command_code']))

  def __getCreditRequest(self):
    tmp = self.chopPayLoad(4)
    credit_request_hex = tmp[2:4] + tmp[0:2]
    self.SMB['credit_request'] = int(credit_request_hex, 16)
    self.showInfo(tmp +"             Credit Request: "+ str(self.SMB['credit_request']))

  def __getFlags(self):
    tmp = self.chopPayLoad(8)
    smb_flags_hex = tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['flags'] = int(str(smb_flags_hex), 16)
    self.showInfo(tmp +"         Flags: "+ str(self.SMB['flags']))

    if (self.SMB['flags'] & 1) == 1:
      self.SMB['request'] = False
    else:
      self.SMB['request'] = True

#----------------------------------------------------------------------------
    smb_flags_set = ('',    \
            'Request',   \
            'Proxyable', \
            'Error',     \
            'T',         \
            'Reserved',  \
            'Reserved',  \
            'Reserved',  \
            'Reserved')

#    for index, smb_flags in enumerate(smb_flags_set):
#      if index:
#        self.showInfo('     ' + self._showBit(self.SMB['flags'], index, smb_flags_set))
#----------------------------------------------------------------------------
#    self.showInfo(self._showBit(self.SMB['flags'], 1, 'Request:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 2, 'Proxyable:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 3, 'Error:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 4, 'T:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 5, 'Reserved:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 6, 'Reserved:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 7, 'Reserved:'))
#    self.showInfo(self._showBit(self.SMB['flags'], 8, 'Reserved:'))
#----------------------------------------------------------------------------
#    if (self.SMB['flags'] & 128) == 128:
#                          self.showInfo("    1... .... = Request: Set"      )
#                          self.SMB['request'] = True
#    else:
#                          self.showInfo("   0... .... = Request: Not Set"  )
#                          self.SMB['request'] = False
#    if (self.SMB['flags'] & 64 ) == 64 : self.showInfo("   .1.. .... = Proxyable: Set"  )
#    else                  : self.showInfo("   .0.. .... = Proxyable: Not Set")
#    if (self.SMB['flags'] & 32 ) == 32 : self.showInfo("   ..1. .... = Error: Set"    )
#    else                  : self.showInfo("   ..0. .... = Error: Not Set"  )
#    if (self.SMB['flags'] & 16 ) == 16 : self.showInfo("   ...1 .... = T: Set"      )
#    else                  : self.showInfo("   ...0 .... = T: Not Set"        )
#    if (self.SMB['flags'] & 8  ) == 8  : self.showInfo("   .... 1... = Reserved: Set"     )
#    else                  : self.showInfo("   .... 0... = Reserved: Not Set" )
#    if (self.SMB['flags'] & 4  ) == 4  : self.showInfo("   .... .1.. = Reserved: Set"     )
#    else                  : self.showInfo("   .... .0.. = Reserved: Not Set" )
#    if (self.SMB['flags'] & 2  ) == 2  : self.showInfo("   .... ..1. = Reserved: Set"     )
#    else                  : self.showInfo("   .... ..0. = Reserved: Not Set" )
#    if (self.SMB['flags'] & 1  ) == 1  : self.showInfo("   .... ...1 = Reserved: Set"     )
#    else                  : self.showInfo("   .... ...0 = Reserved: Not Set" )
#----------------------------------------------------------------------------

  def __getChainOffset(self):
    tmp = self.chopPayLoad(8)
    chain_offset_hex = tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['chain_offset'] = chain_offset_hex
    self.showInfo(tmp +"         Chain Offset: "+ str(self.SMB['chain_offset']))

  def __getMessageID(self):
    tmp = self.chopPayLoad(16)
    message_id_hex = tmp[14:16] + tmp[12:14] + tmp[10:12] + tmp[8:10] + tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['message_id'] = message_id_hex
    self.showInfo(tmp +" Message Id: "+ str(self.SMB['message_id']))

  def __getProcessId(self):
    tmp = self.chopPayLoad(8)
    process_id_hex = tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['process_id'] = process_id_hex
    self.showInfo(tmp +"         Process Id: "+ str(self.SMB['process_id']))

  def __getTreeId(self):
    tmp = self.chopPayLoad(8)
    tree_id_hex = tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['tree_id'] = tree_id_hex
    self.showInfo(tmp +"         Tree Id: "+ str(self.SMB['tree_id']))

  def __getSessionId(self):
    tmp = self.chopPayLoad(16)
    session_id_hex = tmp[14:16] + tmp[12:14] + tmp[10:12] + tmp[8:10] + tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['session_id'] = session_id_hex
    self.showInfo(tmp +" SessionId: "+ str(self.SMB['session_id']))

  def __getSignature(self):
    signature_hex = self.chopPayLoad(32)
    self.SMB['signature'] = signature_hex
    self.showInfo(signature_hex +" Signature: "+ str(self.SMB['signature']))

  def __getStructureSize(self):
    structure_size_hex = self.chopPayLoad(6)
    self.SMB['structure_size'] = structure_size_hex
    self.showInfo(structure_size_hex +"           Structure Size: "+ str(self.SMB['structure_size']))

  def __getOplock(self):
    op_lock_hex = self.chopPayLoad(2)
    self.SMB['op_lock'] = op_lock_hex
    self.showInfo(op_lock_hex +"               Op Lock: "+ str(self.SMB['op_lock']))

  def __getImpersonationLevel(self):
    impersonation_level_hex= self.chopPayLoad(8)
    self.SMB['ImpersonationLevel'] = impersonation_level_hex
    self.showInfo(impersonation_level_hex +"         Impersonation Level: "+ str(self.SMB['ImpersonationLevel']))

  def __getAccessMask(self):
    access_mask_hex = self.chopPayLoad(8)
    self.SMB['access_mask'] = access_mask_hex
    self.showInfo(access_mask_hex +"         AccessMask: "+ str(self.SMB['access_mask']))

  def __getFileAttribute(self):
    FileAttribute_hex = self.chopPayLoad(8)
    self.SMB['file_attribute'] = FileAttribute_hex
    self.showInfo(FileAttribute_hex +"         FileAttribute: "+ str(self.SMB['file_attribute']))

  def __getShareAccess(self):
    ShareAccess_hex = self.chopPayLoad(8)
    self.SMB['share_access'] = ShareAccess_hex
    self.showInfo(ShareAccess_hex +"         ShareAccess: "+ str(self.SMB['share_access']))

  def __getDisposition(self):
    Disposition_hex = self.chopPayLoad(8)
    self.SMB['disposition'] = Disposition_hex
    self.showInfo(Disposition_hex +"         Disposition: "+ str(self.SMB['disposition']))

  def __getCreateOptions(self):
    CreateOptions_hex = self.chopPayLoad(8)
    self.SMB['create_options'] = CreateOptions_hex
    self.showInfo(CreateOptions_hex +"         CreateOptions: "+ str(self.SMB['create_options']))

  def __getFilename(self):
    filename_offset_hex = self.chopPayLoad(4)
    tmp = self.chopPayLoad(4)
    filename_length_hex = tmp[2:4] + tmp[0:2]
    filename_length = int(filename_length_hex, 16)
    blop_tmp = self.chopPayLoad(16)
    self.SMB['filename'] = ''
    if filename_length > 0:
      text_raw_hex = self.chopPayLoad(filename_length * 2)
      counter = 0
      text_hex = ''
      for text in text_raw_hex:
        if counter > 3: counter = 0
        counter += 1
        if counter < 3:
          text_hex += text

      self.SMB['filename'] = text_hex.decode("hex")
      self.result['filename'] = self.SMB['filename']

#      print('Filename: '+ self.SMB['filename'])

    self.showInfo(filename_offset_hex + tmp +"         Filename: "+ str(self.SMB['filename']))
    tmp = self.chopPayLoad(48)

#  def __getBlobOffset(self):
#    BlobOffset_hex = self.chopPayLoad(8)
#    self.SMB['blob_offset'] = BlobOffset_hex
#    self.showInfo(BlobOffset_hex +"         BlobOffset: "+ str(self.SMB['blob_offset']))

#  def __getBlobLength(self):
#    BlobLength_hex = self.chopPayLoad(8)
#    self.SMB['blob_length'] = BlobLength_hex
#    self.showInfo(BlobLength_hex +"         BlobLength: "+ str(self.SMB['blob_length']))

  def __getExtraInfo(self):
    ExtraInfo_hex = self.chopPayLoad(64)
    self.SMB['extra_info'] = ExtraInfo_hex
    self.showInfo(ExtraInfo_hex +" ExtraInfo: "+ str(self.SMB['extra_info']))

  def __getCreateRequest(self):
    self.showInfo("--- SMB Create Request ---------------------------------")
    tmp_hex = self.chopPayLoad(88)

#    self.__getStructureSize()
#    self.__getOplock()
#    self.__getImpersonationLevel()
#    self.__getFlags()
#    self.__reserved(16)
#    self.__getAccessMask()
#    self.__getFileAttribute()
#    self.__getShareAccess()
#    self.__getDisposition()
#    self.__getCreateOptions()
    self.__getFilename()
#    self.__getBlobOffset()
#    self.__getBlobLength()
#    self.__getExtraInfo()

  def rawHexConverted16(self, raw_hex):
    result = raw_hex[14:16] + raw_hex[12:14] + raw_hex[10:12] + raw_hex[8:10] + raw_hex[6:8] + raw_hex[4:6] + raw_hex[2:4] + raw_hex[0:2]
    return result

  def rawHex2Timestamp(self, raw_hex):
    text_hex = self.rawHexConverted16(raw_hex)
    int_hex = int(text_hex, 16)
    float_hex = float(int_hex) / 100000000
#    tmp_int = 100974269 + float_hex
    tmp_int = 101003895 + float_hex
    return tmp_int

  def __getCreateResponse(self):
#    print("IP address source: "+ self.IP['address_source'])
#    print("port source: "+ str(self.TCP['port_source']))
#    print("IP address destination: "+ self.IP['address_destination'])
#    print("port destination: "+ str(self.TCP['port_destination']))
    self.showInfo("--- SMB Create Response ---------------------------------")
#   all_tmp_hex = self.chopPayLoad(240)
#    tmp_hex = self.chopPayLoad(128)
    tmp = self.chopPayLoad(16)
    tmp = self.chopPayLoad(16)
    self.SMB['file_create'] = self.rawHex2Timestamp(tmp)
    tmp = self.chopPayLoad(16)
#    self.SMB['file_last_access'] = self.rawHex2Timestamp(tmp)
    tmp = self.chopPayLoad(16)
#    self.SMB['file_last_write'] = self.rawHex2Timestamp(tmp)
    tmp = self.chopPayLoad(16)
#    self.SMB['file_last_change'] = self.rawHex2Timestamp(tmp)
    tmp = self.chopPayLoad(16)
    tmp = self.chopPayLoad(16)
    tmp_hex = self.rawHexConverted16(tmp)
    self.SMB['end_of_file'] = int(tmp_hex, 16)
    tmp = self.chopPayLoad(8)
    tmp = self.chopPayLoad(8)
    self.SMB['file_id'] = self.chopPayLoad(32)
    tmp_hex = self.chopPayLoad(80)
#    print('file_create: '+ str(self.SMB['file_create']) +' '+ datetime.datetime.utcfromtimestamp(self.SMB['file_create']).strftime('%Y-%m-%d %H:%M:%S'))
#    print('file_last_access: '+ str(self.SMB['file_last_access']) +' '+ datetime.datetime.utcfromtimestamp(self.SMB['file_last_access']).strftime('%Y-%m-%d %H:%M:%S'))
#    print('file_last_write: '+ str(self.SMB['file_last_write']) +' '+ datetime.datetime.utcfromtimestamp(self.SMB['file_last_write']).strftime('%Y-%m-%d %H:%M:%S'))
#    print('file_last_change: '+ str(self.SMB['file_last_change']) +' '+ datetime.datetime.utcfromtimestamp(self.SMB['file_last_change']).strftime('%Y-%m-%d %H:%M:%S'))
#    print('end_of_file: '+ str(self.SMB['end_of_file']))

#    self.result['filename'] = self.SMB['filename']
    self.result['file_size'] = self.SMB['end_of_file']
    self.result['ip_address_source'] = self.IP['address_source']
    self.result['port_source'] = self.TCP['port_source']
    self.result['ip_address_destination'] = self.IP['address_destination']
    self.result['port_destination'] = self.TCP['port_destination']
    self.result['timestamp'] = self.SMB['file_create']
    self.result['date_time'] = datetime.datetime.utcfromtimestamp(self.result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')

  def __getInfoRequest(self):
    self.showInfo("--- SMB Info Request ---------------------------------")
    tmp_hex = self.chopPayLoad(80)

  def __getInfoResponse(self):
    self.showInfo("--- SMB Info Response ---------------------------------")
    tmp_hex = self.chopPayLoad(336)

  def __getCloseRequest(self):
    self.showInfo("--- SMB Close Request ---------------------------------")
    tmp_hex = self.chopPayLoad(48)

  def __getCloseResponse(self):
    self.showInfo("--- SMB Close Response ---------------------------------")
    tmp_hex = self.chopPayLoad(120)

  def __getFindRequest(self):
    self.showInfo("--- SMB Find Request ---------------------------------")
    tmp_hex = self.chopPayLoad(80)

  def __getFindResponse(self):
    self.showInfo("--- SMB Find Response ---------------------------------")
    tmp_hex = self.chopPayLoad(240)

  def __getReadRequest(self):
    self.showInfo("--- SMB Read Request ---------------------------------")
    tmp_hex = self.chopPayLoad(96)

  def __getReadResponse(self):
    self.showInfo("--- SMB Read Response ---------------------------------")
    tmp_hex = self.chopPayLoad(32)

  def getSMBHeader(self):
    self.showInfo("--- SMB Header ----------------------------------------")
    self.__getProtocolId()
    self.__getHeaderLength()
    self.__getCreditCharge()
    self.__getChannelSequence()
    self.__reserved(4)
    self.__getCommand()
    self.__getCreditRequest()
    self.__getFlags()
    self.__getChainOffset()
    self.__getMessageID()
    self.__getProcessId()
    self.__getTreeId()
    self.__getSessionId()
    self.__getSignature()

  def __getReadRequest(self):
    self.showInfo("--- SMB Read Response ---------------------------------")
    tmp = self.chopPayLoad(8)
    tmp = self.chopPayLoad(8)
    length_size_hex = tmp[6:8] + tmp[4:6] + tmp[2:4] + tmp[0:2]
    self.SMB['file_length_size'] = int(length_size_hex, 16)
#    print(self.SMB['file_length_size'])
    tmp = self.chopPayLoad(16)


  def __getReadResponse(self):
    pass

  def collectSMB(self):
    self.getSMBHeader()
#    print("--> Command: "+ self.SMB['command_code'])
    if self.SMB['request']:
      if self.SMB['command_code'] == '0005':
        self.__getCreateRequest()
      elif self.SMB['command_code'] == '0006':
        self.__getCloseRequest()
      elif self.SMB['command_code'] == '0008':
        self.__getReadRequest()
      elif self.SMB['command_code'] == '0010':
        self.__getInfoRequest()
      elif self.SMB['command_code'] == '0E00':
        self.__getFindRequest()
    else:
      if self.SMB['command_code'] == '0005':
        self.__getCreateResponse()
      elif self.SMB['command_code'] == '0006':
        self.__getCloseResponse()
      elif self.SMB['command_code'] == '0008':
        self.__getReadResponse()
      elif self.SMB['command_code'] == '0010':
        self.__getInfoResponse()
      elif self.SMB['command_code'] == '0E00':
        self.__getFindResponse()


#    self.__getCommandCode()
#    if not self.__checkFilter_DiameterCommandCode(): return False

#    self.__getApplicationId()
#    if not self.__checkFilter_DiameterApplicationId(): return False

#    print("Eth Counter: " + str(self._EthernetByteCounter))
#    print("TCP Counter: " + str(self._TCPByteCounter))
#    print("IP Counter: "  + str(self._IPByteCounter))

    return True

  def showEthernet(self):
    if self._Output_MACAddressDestination:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'MAC_Address_Dest=' + self.Ethernet['address_destination']

    if self._Output_MACAddressSource:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'MAC_Address_Src=' + self.Ethernet['address_source']

  def showIP(self):
    if self._Output_IPAddressSource:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'IP_Address_Src=' + self.IP['address_source']

    if self._Output_IPAddressDestination:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'IP_Address_Dest=' + self.IP['address_destination']

  def showTCP(self):
    if self._Output_PortSource:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'Port_Src=' + str(self.TCP['port_source'])

    if self._Output_PortDestination:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'Port_Dest=' + str(self.TCP['port_destination'])

  def showSMB(self):
    if self._Output_SMBRequest:
      if self._TextOutput: self._TextOutput += '|'
#      self._TextOutput += 'Request=' + str(self.SMB['request'])
      if self.SMB['request']:
        self._TextOutput += 'Request'
      else:
        self._TextOutput += 'Answer'

#    if self._Output_NetBIOS_SessionService:
#      if self._TextOutput: self._TextOutput += '|'
#      self._TextOutput += self.dictcommands2name(self.SMB['command_code']) + '('+ str(self.SMB['command_code']) + ')'

    if self._Output_SMBApplicationId:
      if self._TextOutput: self._TextOutput += '|'
      self._TextOutput += 'ApplicationId=' + str(self.SMB['application_id'])


    self.showInfo("--- CUSTOM OUTPUT -----")
    print(self._TextOutput)

  def collect(self):
    self._reset()
    self.collectFrame()

    self.collectEthernet()
    if not self.__checkFilter_MACAddressDestination(): return False
    if not self.__checkFilter_MACAddressSource()     : return False

    self.collectIP()
    if not self.__checkFilter_IPAddressSource()     : return False
    if not self.__checkFilter_IPAddressDestination(): return False

    self.collectTCP()
    if not self.__checkFilter_PortSource()     : return False
    if not self.__checkFilter_PortDestination(): return False

    if self.IP['total_length'] > 55:
      self.collectNetBIOS()
      while self._ByteCounter < (self.NetBIOS['length'] * 2) - 16:
        self.collectSMB()

  def writeJSON(self):
    with open('result.json', 'w') as fp:
      json.dump(self.result, fp, indent=2)


