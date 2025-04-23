import os
import sys
import logging
from LibPython import Logger
from WebDav import WebDav
from Vault import Vault,Config

Logger.SetLevel(logging.INFO)
Logger.SetPrefix('Vault')


# Crypt.Test()
if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
  Vault.Root = sys.argv[1]
os.chdir(Vault.Root)
Config.Load()
WebDav().Run()
