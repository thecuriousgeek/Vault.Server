import os
import sys
import getopt
import logging
from LibPython import Logger,Xml
import Web
import Vault

Logger.SetLevel(logging.INFO)
Logger.SetPrefix('Vault')

_Aliases=[]
opts,args = getopt.getopt(sys.argv[1:],'h:f:',['hostname','folder'])
for opt,arg in opts:
  if opt=='-f': 
    if os.path.isdir(arg): os.chdir(arg)
    else: raise f'Folder {arg} not a vaild directory'
  if opt=='-h': _Aliases.append(arg)

Vault.Config.Load()
Web.Run(_Aliases)
