import os
import pathlib
from datetime import datetime, timezone,timedelta
import re
import urllib.parse
import threading
import socket
from flask import Flask, Request, Response, request, redirect,send_file
import mimetypes
from Vault import Vault, Config
from LibPython import Logger, Dynamic


App = Flask('WebDAV')
def SanitizeXml(pWhat: str): return pWhat.replace( '&', '&amp;').replace('<', '&lt;')
# def FormatTime(pWhat: float): return datetime.fromtimestamp(pWhat, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z')
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


@App.before_request
def BeforeRequest():
  _Context = Dynamic()
  request.Context = _Context
  _Context.Start = datetime.now()
  _Context.Name, _Context.Path = SplitURL(request.url)
  _Context.Method = request.method
  _Context.User = request.authorization['username'] if request.authorization else None
  _Context.Password = request.authorization['password'] if request.authorization else None
  _Context.Logger = Logger(f'WebDav.{_Context.Name}.{_Context.Method}.{_Context.Path}')
  if _Context.Name.lower() == "admin": return None
  if not _Context.Name in Config.Vaults(): return Response(f'{_Context.Path}:Not Found', 404)
  _Context.Vault = Config.Open(_Context.Name, _Context.Password)
  if not _Context.Vault: return Response(None, 401, {'WWW-Authenticate': 'Basic realm="Vault"'})
  return None

@App.after_request
def AfterRequest(pResponse):
  request.Context.Logger.Info(f'{pResponse.status_code} in {(datetime.now()-request.Context.Start).total_seconds()}s')
  return pResponse


class WebDav:
  Locks = []
  def Run(self):
    _Name = socket.gethostname()
    _Https = threading.Thread(target=self.App.run, kwargs={'host':'0.0.0.0','port':443,'ssl_context': (f'{_Name}.crt', f'{_Name}.key')})
    _Http = threading.Thread(target=self.App.run, kwargs={'host':'0.0.0.0','port':80})
    _Https.start()
    _Http.start()
    _Https.join()
    _Http.join()
    # self.App.run(host='0.0.0.0', port=self.Port,ssl_context=(f'{_Name}.crt', f'{_Name}.key'))

  def __init__(self):
    # super().__init__('WebDav')
    # log = logging.getLogger('werkzeug')
    # log.setLevel(logging.ERROR)
    self.App = App  # Global instance
    self.App.secret_key = "MyVault"
    self.Logger = Logger('WebDAV.Vault')
    self.App.add_url_rule('/admin', 'AdminHome',WebDav.OnAdminHome, methods=['GET'])
    self.App.add_url_rule('/admin/new', 'AdminNew',WebDav.OnAdminNew, methods=['POST'])
    self.App.add_url_rule('/admin/browse/<path:pPath>','AdminBrowse', WebDav.OnAdminBrowse, methods=['GET'])
    self.App.add_url_rule('/admin/cert', 'Certificate',WebDav.OnAdminCert, methods=['GET'])
    self.App.add_url_rule('/<path:pPath>', 'Options',WebDav.OnOptions, methods=['OPTIONS'])
    self.App.add_url_rule('/<path:pPath>', 'Head',WebDav.OnHead, methods=['HEAD'])
    self.App.add_url_rule('/<path:pPath>', 'Get',WebDav.OnGet, methods=['GET'])
    self.App.add_url_rule('/<path:pPath>', 'Put',WebDav.OnPut, methods=['PUT'])
    self.App.add_url_rule('/<path:pPath>', 'Delete',WebDav.OnDelete, methods=['DELETE'])
    self.App.add_url_rule('/<path:pPath>', 'Lock',WebDav.OnLock, methods=['LOCK'])
    self.App.add_url_rule('/<path:pPath>', 'Unlock',WebDav.OnUnlock, methods=['UNLOCK'])
    self.App.add_url_rule('/<path:pPath>', 'Mkdir',WebDav.OnMkdir, methods=['MKCOL'])
    self.App.add_url_rule('/<path:pPath>', 'Move',WebDav.OnMove, methods=['MOVE'])
    self.App.add_url_rule('/<path:pPath>', 'PropGet',WebDav.OnPropGet, methods=['PROPFIND'])
    self.App.add_url_rule('/<path:pPath>', 'PropPut',WebDav.OnPropSet, methods=['PROPPATCH'])

      
  async def OnAdminHome():
    _Response = '<html><head><title>My Vaults</title></head><body><h2>The following vaults are configured</h2><ul>'
    for _Vault in Config.Vaults():
      _Response += f'<li><a href="/admin/browse/{_Vault}">{_Vault}</a></li>'
    _Response += f'</ul><p>'
    _Response += '<h2>Create New Vault</h2><form action="/admin/new" method="POST">Name:<input name="name"><br>Password:<input name="password"><br><input type="submit" value="Create"></form>'
    _Response += '<p><h2>Certificate</h2><a href=/admin/cert>Download</a>'
    _Response += '</body></html>'
    return Response(_Response, 200,headers={})

  async def OnAdminNew():
    if not 'name' in request.form or not 'password' in request.form:
      return Response('Need a name and password for vault<p><a href=/admin>Back</a>', 200)
    _Vault = Config.Create(request.form['name'], request.form['password'])
    if not _Vault:
      return Response('Cannot create vault<p><a href=/admin>Back</a>', 200)
    return redirect('/admin')

  async def OnAdminBrowse(pPath:str):
    _Name,_Path = SplitURL(pPath)
    if not _Name in Config.Vaults():
      return Response(f'Vault {_Name}:Not Found', 404)
    _Vault = Config.Open(_Name, request.Context.Password)
    if not _Vault: return Response(None, 401, {'WWW-Authenticate': 'Basic realm="Vault"'})
    if os.path.isfile(_Vault.GetFileName(_Path)):
      from io import BytesIO
      _Buff = BytesIO()
      for d in _Vault.CopyFrom(_Path):
        _Buff.write(d)
      _Buff.seek(0)
      return send_file(_Buff,download_name=os.path.basename(_Path), mimetype=mimetypes.guess_type(_Path)[0])
    _Response = f'<html><head><title>Browse {_Vault.Name}</title></head><body><h2>Files in {_Path}</h2><ul>'
    for _File in _Vault.ScanDir(_Path):
      _Info = pathlib.Path(_Vault.GetFileName(_File))
      _FileName = os.path.basename(_File)
      _Response += f'<li><a href="/admin/browse/{_Vault.Name}/{os.path.join(_Path,_FileName)[1:]}">{SanitizeXml(_FileName)}</a>'
      if _Info.is_dir():
        _Response += f'</li>'
      else:
        _Response += f' - {_Info.stat().st_size}</li>'
    _Response += '</ul><p>'
    return Response(_Response,200)

  async def OnAdminCert():
    c = f'{socket.gethostname()}.crt'
    return send_file(open(c,'rb'),download_name=c, as_attachment=True, mimetype='application/x-x509-ca-cert')

  async def OnOptions(pPath:str):
    _Headers = {}
    _Headers['Allow'] = 'OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND'
    _Headers["Dav"] = '1, 2'
    return Response('', 200, headers=_Headers)

  async def OnHead(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    return Response('', 200,)

  async def OnGet(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    return Response(request.Context.Vault.CopyFrom(request.Context.Path), mimetype=mimetypes.guess_type(request.Context.Path)[0])

  async def OnPut(pPath:str):
    request.Context.Vault.CopyTo(request.Context.Path, request.stream)
    return Response('Created', 200)

  async def OnDelete(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    request.Context.Vault.Delete(request.Context.Path)
    return Response('Gone', 200)

  async def OnMove(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    _Target = SplitURL(request.headers["Destination"])[1]  # Leading and trailing / of Vault name
    request.Context.Vault.Move(request.Context.Path, f'/{_Target}')
    return Response('Done', 200)

  async def OnLock(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    _Name = request.Context.Vault.Name + '/' + request.Context.Path
    if _Name in WebDav.Locks:
      return Response('Already Locked', 423)
    WebDav.Locks.append(_Name)
    _Body = request.data.decode('utf-8')
    _User = GetRegexMatch('<D:owner><D:href>(.*)</D:href></D:owner>', _Body)
    _Token = datetime.now().timestamp()
    _Response = f'<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth><D:owner><D:href>{_User}</D:href></D:owner><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>{_Token}</D:href></D:locktoken><D:lockroot><D:href>{SanitizeXml(request.Context.Path)}</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>'
    return Response(_Response, 200)

  async def OnUnlock(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    _Name = request.Context.Vault.Name + '/' + request.Context.Path
    if not _Name in WebDav.Locks:
      return Response('Not Locked', 404)
    WebDav.Locks.remove(_Name)
    return Response('', 204)

  async def OnMkdir(pPath:str):
    if not request.Context.Vault.CreateDirectory(request.Context.Path):
      return Response('Exists', 409)
    return Response('Created', 201)

  async def OnPropGet(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    _Deep = request.headers.get('Depth', '0') == '1'
    _Files = [request.Context.Path]
    if _Deep:
      _Files.extend(request.Context.Vault.ScanDir(request.Context.Path))
    _Response = '<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">'
    for _File in _Files:
      if request.Context.Vault.IsHidden(_File):
        continue
      _Info = pathlib.Path(request.Context.Vault.GetFileName(_File))
      if _Info.is_dir():
        _Response += f'<D:response><D:href>/{request.Context.Vault.Name}{SanitizeXml(_File)}</D:href><D:propstat><D:prop><D:displayname>{SanitizeXml(os.path.basename(_File))}</D:displayname><D:resourcetype><D:collection xmlns:D="DAV:"/></D:resourcetype><D:getlastmodified>{FormatTime(_Info.stat().st_mtime)}</D:getlastmodified><D:supportedlock><D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
      else:
        _Response += f'<D:response><D:href>/{request.Context.Vault.Name}{SanitizeXml(_File)}</D:href><D:propstat><D:prop><D:displayname>{SanitizeXml(os.path.basename(_File))}</D:displayname><D:resourcetype></D:resourcetype><D:getcontentlength>{_Info.stat().st_size}</D:getcontentlength><D:creationdate>{FormatTime(_Info.stat().st_mtime)}</D:creationdate><D:getlastmodified>{FormatTime(_Info.stat().st_mtime)}</D:getlastmodified><D:supportedlock><D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
    _Response += '</D:multistatus>'
    return Response(_Response, 207, content_type='text/xml; charset=utf-8')

  async def OnPropSet(pPath:str):
    if not request.Context.Vault.Exists(request.Context.Path):
      return NotFound(request.Context.Vault.Name,request.Context.Path)
    _Body = request.data.decode('utf-8')
    _CreationTime = GetRegexMatch('<Z:Win32CreationTime>(.*)</Z:Win32CreationTime>', _Body)
    _LastAccessTime = GetRegexMatch('<Z:Win32LastAccessTime>(.*)</Z:Win32LastAccessTime>', _Body)
    _LastModifiedTime = GetRegexMatch('<Z:Win32LastModifiedTime>(.*)</Z:Win32LastModifiedTime>', _Body)
    _FileAttributes = GetRegexMatch('<Z:Win32FileAttributes>(.*)</Z:Win32FileAttributes>', _Body)

    # "application/xml; charset=utf-8"
    _Response = f'<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{SanitizeXml(request.Context.Path)}</D:href><D:propstat><D:prop>'
    _Patches = ''
    _Info = pathlib.Path(request.Context.Vault.GetFileName(request.Context.Path))
    if (_Info.is_file):
      if _CreationTime:
        _Response += '<Win32CreationTime xmlns="urn:schemas-microsoft-com:"></Win32CreationTime>'
        _Patches += 'CreationTime,'
      if _LastAccessTime:
        _Response += '<Win32LastAccessTime xmlns="urn:schemas-microsoft-com:"></Win32LastAccessTime>'
        _Patches += 'AccessTime,'
      if _LastModifiedTime:
        _Response += '<Win32LastModifiedTime xmlns="urn:schemas-microsoft-com:"></Win32LastModifiedTime>'
        _Patches += 'WriteTime,'
      if _FileAttributes:
        _Response += '<Win32FileAttributes xmlns="urn:schemas-microsoft-com:"></Win32FileAttributes>'
        _Patches += 'Attributes,'
    _Response += '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>'
    request.Context.Vault.Update(request.Context.Path, created=_CreationTime,accessed=_LastAccessTime, modified=_LastModifiedTime)
    return Response(_Response, 200, content_type='application/xml; charset=utf-8')
