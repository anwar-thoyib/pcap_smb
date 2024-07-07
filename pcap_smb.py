#!/usr/bin/python
"""
Created on Mon Jul  7 14:27:13 2024

@author: anwar.thoyib@gmail.com
"""
import sys
from c_smb import SMB

##############################################################################
if __name__ == "__main__":

  mydebug = False

# use file handler ----------------------------------------------------------
  fileinput = ''
  if len(sys.argv) > 1:
    fileinput = sys.argv[1]
    if len(sys.argv) > 2:
      if sys.argv[2] == 'debug':
        mydebug = True
  else:
    print("Need parameter input: file!")
    exit(0)

  fin = open(fileinput, "rb")
  tmp = fin.read()
  fin.close()

  myinput = tmp.encode("hex")

# use standard inpout --------------------------------------------------------
#  myinput = sys.stdin.read()

#-----------------------------------------------------------------------------
  mySMB = SMB()
  if mydebug:
    mySMB.setDebug(True)

  mySMB.setLine(myinput)
  while not mySMB.EOF:
    if mySMB.collect():
      mySMB.showEthernet()
      mySMB.showTCP()
      mySMB.showIP()
      mySMB.showSMB()

  mySMB.showInfo("--- EOF -------------------------------------------------")
  mySMB.writeJSON()
  print("Result (result.json):")
  print(mySMB.result)
