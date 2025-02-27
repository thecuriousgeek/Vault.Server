import os
import sys
import logging
import threading
from datetime import datetime
import time
from LibPython import IniFile, Logger
from WebDav import WebDav
from Vault import Vault

Logger.SetLevel(logging.INFO)
Logger.SetPrefix('Vault')

def Watcher():
  _Logger = Logger('Watcher')
  _IniFile = IniFile(f'{Vault.Folder}/Vault.ini')
  s = _IniFile.Get('Setting','Timeout')
  _Timeout = int(s) if s else 600
  _Logger.Info(f'Will close vaults after {_Timeout} seconds idle')
  while True:
    time.sleep(5)
    _Now = datetime.now()
    for _Vault in Vault.Instances:
      if _Vault.Mounted and (_Now-_Vault.LastUse).total_seconds()>_Timeout: 
        _Logger.Warning(f'Closing {_Vault.Name} after {_Timeout} seconds idle')
        _Vault.Unmount()

# Crypt.Test()
Vault.Folder = sys.argv[1] if len(sys.argv)>1 and os.path.isdir(sys.argv[1]) else './data'
Vault.Load()
threading.Thread(target=lambda: Watcher()).start()
WebDav().Start(False)
