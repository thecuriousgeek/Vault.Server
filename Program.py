import os
import sys
import logging
import getopt
import socket
import ipaddress
import re
from datetime import datetime,timedelta,timezone
from LibPython import Logger
from WebDav import WebDav,HOSTNAME
from Vault import Vault,Config

Logger.SetLevel(logging.INFO)
Logger.SetPrefix('Vault')

def GenerateCerts(pName:str,pAliases:list[str]):
  from cryptography import x509
  from cryptography.x509.oid import NameOID
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  
  _Key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend(),)    
  _Name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, pName)])
  _AltNames = [x509.DNSName(x) for x in pAliases]
  for n in pAliases:
    if re.match("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",n):
      _AltNames.append(x509.IPAddress(ipaddress.ip_address(n)))
  _SubAltNames = x509.SubjectAlternativeName(_AltNames)
  _Constraints = x509.BasicConstraints(ca=True, path_length=0)
  _Now = datetime.now(tz=timezone.utc)
  _Cert = (
    x509.CertificateBuilder()
      .subject_name(_Name)
      .issuer_name(_Name)
      .public_key(_Key.public_key())
      .serial_number(1000)
      .not_valid_before(_Now)
      .not_valid_after(_Now+timedelta(days=10*365))
      .add_extension(_Constraints, False)
      .add_extension(_SubAltNames, False)
      .sign(_Key, hashes.SHA256(), default_backend())
  )
  _CertData = _Cert.public_bytes(encoding=serialization.Encoding.PEM)
  _KeyData = _Key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
  )
  with open(f'{pName}.crt', "wt") as f:
    f.write(_CertData.decode('utf-8'))
  with open(f'{pName}.key', "wt") as f:
    f.write(_KeyData.decode('utf-8'))

_Aliases = [socket.gethostname(),socket.getfqdn()]
opts,args = getopt.getopt(sys.argv[1:],'h:f:',['hostname','folder'])
for opt,arg in opts:
  if opt=='-f': 
    if os.path.isdir(arg): os.chdir(arg)
    else: raise f'Folder {arg} not a vaild directory'
  if opt=='-h': _Aliases.append(arg)

if not os.path.exists(f'{HOSTNAME}.key') or not os.path.exists(f'{HOSTNAME}.crt'):
  print('Generating certificates')
  GenerateCerts(HOSTNAME,_Aliases)
Config.Load()
WebDav().Run()
