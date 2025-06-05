import os
import logging
from datetime import datetime, timezone,timedelta
import re
import urllib.parse
import threading
import socket
import ipaddress
from flask import Flask, Response, request, send_file, redirect, render_template
import mimetypes
from Vault import Config
from LibPython import Logger, Dynamic
from Dav import Dav

App = Flask('WebDAV',static_folder='static')
HOSTNAME=socket.gethostname()

def SanitizeXml(pWhat: str): return pWhat.replace( '&', '&amp;').replace('<', '&lt;')
def FormatTime(pWhat: float): return datetime.fromtimestamp(pWhat, tz=timezone.utc).strftime('%a, %b %d %Y %H:%M:%S %Z')
def SplitURL(pURI: str) -> tuple:
  _Path = urllib.parse.unquote(urllib.parse.urlparse(pURI).path)
  if _Path[0]=='/': _Path = _Path[1:]
  _Parts = _Path.split('/', 1)
  return (_Parts[0] if len(_Parts) > 0 else None, f'/{_Parts[1]}' if len(_Parts) > 1 else '/')
def GetRegexMatch(pPattern: str, pString: str):
  _Matches = re.search(pPattern, pString)
  return _Matches.group(1) if _Matches else None
def NotFound(pVault:str,pPath:str): return Response(f'{pPath}-Not Found in {pVault}', 404)

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

def Run(pNames:list):
  _Aliases = [HOSTNAME,socket.getfqdn()].append(pNames)
  if not os.path.exists(f'{HOSTNAME}.key') or not os.path.exists(f'{HOSTNAME}.crt'):
    print('Generating certificates')
    GenerateCerts(HOSTNAME,_Aliases)
  Web().Run()

@App.before_request
def BeforeRequest():
  _Context = Dynamic()
  request.Context = _Context
  _Context.Start = datetime.now()
  _Context.Logger = Logger(f'WebDav.{request.method}-{request.path}')
  return None

@App.after_request
def AfterRequest(pResponse):
  request.Context.Logger.Info(f'{pResponse.status_code} - {pResponse.content_length or "stream"} bytes in {(datetime.now()-request.Context.Start).total_seconds()}s')
  return pResponse


class Web:
  Locks = []
  def Run(self):
    _Https = threading.Thread(target=self.App.run, kwargs={'host':'0.0.0.0','port':443,'ssl_context': (f'{HOSTNAME}.crt', f'{HOSTNAME}.key')})
    _Http = threading.Thread(target=self.App.run, kwargs={'host':'0.0.0.0','port':80})
    _Https.start()
    _Http.start()
    _Https.join()
    _Http.join()

  def __init__(self):
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    self.App = App  # Global instance
    self.App.secret_key = "MyVault"
    self.Logger = Logger('WebDAV')
    self.App.add_url_rule('/', 'Home',Web.OnHome, methods=['GET','POST'])
    self.App.add_url_rule('/static/<path:pFile>', 'Static',Web.OnStatic, methods=['GET'])
    # self.App.add_url_rule('/admin', 'Home',Web.OnHome, methods=['GET'])
    self.App.add_url_rule('/cart', 'Certificate',Web.OnCert, methods=['GET'])
    self.App.add_url_rule('/<string:pVault>', 'Vault',Web.OnVault, methods=['OPTIONS','PROPFIND'])
    self.App.add_url_rule('/<string:pVault>/', 'Vault',Web.OnVault, methods=['OPTIONS','PROPFIND'])
    self.App.add_url_rule('/<string:pVault>/<path:pPath>', 'Vault',Web.OnVault, methods=['HEAD','GET','PUT','DELETE','LOCK','UNLOCK','MKCOL','MOVE','PROPFIND','PROPPATCH'])

  def OnCert():
    c = f'{socket.gethostname()}.crt'
    return send_file(open(c,'rb'),download_name=c, as_attachment=True, mimetype='application/x-x509-ca-cert')

  def OnStatic(pFile:str):
   return send_file(pFile)

  def OnHome():
    if request.method == 'POST':
      if not 'name' in request.form or not 'password' in request.form:
        return Response('Need a name and password for vault<p><a href=/>Back</a>', 200)
      _Vault = Config.Create(request.form['name'], request.form['password'])
      if not _Vault:
        return Response('Cannot create vault<p><a href=/admin>Back</a>', 200)
      return redirect('/')
    else:
      _Response = '<html><head><title>My Vaults</title></head><body><h2>The following vaults are configured</h2><ul>'
      for _Vault in Config.Vaults():
        _Response += f'<li><a href="/static/browse.html?path={_Vault}">{_Vault}</a></li>'
      _Response += f'</ul><p>'
      _Response += '<h2>Create New Vault</h2><form action="/" method="POST">Name:<input name="name"><br>Password:<input name="password"><br><input type="submit" value="Create"></form>'
      _Response += f'<p><h2>Certificate</h2><a href=/cert>Download</a>'
      _Response += '</body></html>'
      return Response(_Response, 200,headers={})

  # def OnAdmin(pPath:str=None):
  #   return Admin.OnNew(request.form) if request.method == 'POST' else Admin.OnHome()

  # def OnBrowse(pVault:str=None,pPath:str='/'):
  #   if not pVault: return Browse.OnFile(pPath)
  #   if not pVault in Config.Vaults():
  #     return Response(f'Vault {pVault}:Not Found', 404)
  #   _Password = request.authorization['password'] if request.authorization else None
  #   _Vault = Config.Open(pVault, _Password)
  #   if not _Vault: return Response(None, 401, {'WWW-Authenticate': 'Basic realm="Vault"'})
  #   return Browse.OnVault(_Vault,pPath)

  def OnVault(pVault:str,pPath:str='/'):
    if not pVault in Config.Vaults():
      return Response(f'Vault {pVault}:Not Found', 404)
    _Password = request.authorization['password'] if request.authorization else None
    _Vault = Config.Open(pVault, _Password)
    if not pPath.startswith('/'): pPath = '/' + pPath
    if not _Vault: return Response(None, 401, {'WWW-Authenticate': 'Basic realm="Vault"'})
    if request.method == 'OPTIONS':
      return Dav.OnOptions(_Vault)
    if request.method == 'HEAD':
      return Dav.OnHead(_Vault,pPath)
    if request.method == 'GET': 
      return Dav.OnGet(_Vault,pPath)
    if request.method == 'PUT': 
      return Dav.OnPut(_Vault,pPath)
    if request.method == 'DELETE': 
      return Dav.OnDelete(_Vault,pPath)
    if request.method == 'LOCK': 
      return Dav.OnLock(_Vault,pPath)
    if request.method == 'UNLOCK': 
      return Dav.OnUnlock(_Vault,pPath)
    if request.method == 'MKCOL': 
      return Dav.OnMkCol(_Vault,pPath)
    if request.method == 'MOVE': 
      return Dav.OnMove(_Vault,pPath,request.headers['Destination'])
    if request.method == 'PROPFIND': 
      return Dav.OnPropFind(_Vault,pPath)
    if request.method == 'PROPPATCH': 
      return Dav.OnPropPatch(_Vault,pPath)
    # return Dav.OnVault(_Vault,pPath)