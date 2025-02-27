import os
import pathlib
from datetime import datetime,timezone
import re
import urllib.parse
import base64
from flask import Flask,Request,Response,request,redirect
import mimetypes
from Vault import Vault
from LibPython import Logger, AsyncTask

class WebDav(AsyncTask):
  def SanitizeXml(pWhat:str): return pWhat.replace('&','&amp;').replace('<','&lt;')
  class Context:
    @property
    def FileName(self)->str:return self.Vault.GetFileName(self.Path)
    
    def SplitURL(pURI:str)->tuple:
      _Path = urllib.parse.unquote(urllib.parse.urlparse(pURI).path)
      _Parts = _Path[1:].split('/',1)
      return (_Parts[0] if len(_Parts)>0 else None, f'/{_Parts[1]}' if len(_Parts)>1 else '/')
    
    def __init__(self,pRequest:Request):
      v, self.Path = WebDav.Context.SplitURL(request.url)
      self.Vault:Vault = Vault.Get(v)
      self.Method = pRequest.method
      self.Logger = Logger(f'WebDav.{self.Vault.Name if self.Vault else ""}.{self.Method}.{self.Path}')

    @property
    def NotFound(self):
      return Response(f'{self.Path}:Not Found',404)
    
  Instances=[]
  Locks=[]
  def GetRegexMatch(pPattern:str,pString:str):
    _Matches = re.search(pPattern,pString)
    return _Matches.group(1) if _Matches else None

  def VaultRequest(pMethod):
    async def Wrapper(**kwargs):
      _Context = WebDav.Context(request)
      if not _Context.Vault: return Response('No such vault')
      _Context.Vault.LastUse = datetime.now();
      _Result = await pMethod(_Context)
      return _Result
    return Wrapper

  def __init__(self):
    super().__init__('WebDav')
    # log = logging.getLogger('werkzeug')
    # log.setLevel(logging.ERROR)
    self.App = Flask(__name__)
    self.App.secret_key = "MyVault"
    self.Port = 5000
    self.Logger = Logger('WebDAV.Vault')    
    self.App.add_url_rule('/','Admin',WebDav.OnAdmin,methods=['GET'])
    self.App.add_url_rule('/<string:pVault>','Home',WebDav.OnAdmin,methods=['GET'])
    self.App.add_url_rule('/<path:pPath>','Options',WebDav.OnOptions,methods=['OPTIONS'])
    self.App.add_url_rule('/<path:pPath>','Head',WebDav.OnHead,methods=['HEAD'])
    self.App.add_url_rule('/<path:pPath>','Get',WebDav.OnGet,methods=['GET'])
    self.App.add_url_rule('/<path:pPath>','Put',WebDav.OnPut,methods=['PUT'])
    self.App.add_url_rule('/<path:pPath>','Delete',WebDav.OnDelete,methods=['DELETE'])
    self.App.add_url_rule('/<path:pPath>','Lock',WebDav.OnLock,methods=['LOCK'])
    self.App.add_url_rule('/<path:pPath>','Unlock',WebDav.OnUnlock,methods=['UNLOCK'])
    self.App.add_url_rule('/<path:pPath>','Mkdir',WebDav.OnMkdir,methods=['MKCOL'])
    self.App.add_url_rule('/<path:pPath>','Move',WebDav.OnMove,methods=['MOVE'])
    self.App.add_url_rule('/','PropGet',WebDav.OnPropGet,methods=['PROPFIND'])
    self.App.add_url_rule('/<path:pPath>','PropGet',WebDav.OnPropGet,methods=['PROPFIND'])
    self.App.add_url_rule('/<path:pPath>','PropPut',WebDav.OnPropSet,methods=['PROPPATCH'])
    WebDav.Instances.append(self)

  async def Run(self):
    self.Logger.Info(f'Starting on {self.Port}')
    self.App.run(host='0.0.0.0',port=self.Port)#,ssl_context=('./server.crt','./server.key'))

  async def OnAdmin(pVault:str=None):
    if pVault is None:
      _Response = '<html><head><title>My Vaults</title></head><body><h2>The following vaults are configured</h2><ul>'
      for _Vault in Vault.Instances:
        _Response += f'<li><a href="/{_Vault.Name}">{_Vault.Name}</a> - is {"Open" if _Vault.Mounted else "Closed"}</li>'
      _Response += '</ul></body></html>'
      return Response(_Response,200)
    else:
      _Context = WebDav.Context(request)
      if _Context.Vault is None: return Response('No such vault',404)
      if _Context.Vault.Mounted: return redirect('/')
      _Header = request.headers.get('Authorization')
      if not _Header: return Response(None,401,{'WWW-Authenticate':'Basic'})
      _Auth = base64.b64decode(_Header.split()[-1]).decode('utf-8').split(':',1)
      if not _Context.Vault.Validate(_Auth[1]): return Response(None,401,{'WWW-Authenticate':'Basic'})
      _Context.Vault.Mount(_Auth[1])
      _Context.Vault.LastUse = datetime.now()
      return redirect('/')
      
  @VaultRequest
  async def OnOptions(pContext:Context):
    _Headers={}
    _Headers['Allow'] = 'OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND'
    _Headers["Dav"] = '1, 2'
    return Response('',200,headers=_Headers)

  @VaultRequest
  async def OnHead(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    return Response('',200,)

  @VaultRequest
  async def OnGet(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    return Response(pContext.Vault.CopyFrom(pContext.Path),mimetype=mimetypes.guess_type(pContext.Path)[0])

  @VaultRequest
  async def OnPut(pContext:Context):
    pContext.Vault.CopyTo(pContext.Path,request.stream)
    return Response('Created',200)

  @VaultRequest
  async def OnDelete(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    pContext.Vault.Delete(pContext.Path)
    return Response('Gone',200)

  @VaultRequest
  async def OnMove(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    _Target = WebDav.Context.SplitURL(request.headers["Destination"])[1] #Leading and trailing / of Vault name
    pContext.Vault.Move(pContext.Path,f'/{_Target}')
    return Response('Gone',200)

  @VaultRequest
  async def OnLock(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    if pContext.Path in WebDav.Locks: return Response('Already Locked',423)
    WebDav.Locks.append(pContext.Path)
    _Body = request.data.decode('utf-8')
    _User = WebDav.GetRegexMatch('<D:owner><D:href>(.*)</D:href></D:owner>',_Body)
    _Token = datetime.now().timestamp()
    _Response = f'<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth><D:owner><D:href>{_User}</D:href></D:owner><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>{_Token}</D:href></D:locktoken><D:lockroot><D:href>{WebDav.SanitizeXml(pContext.Path)}</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>'
    return Response(_Response,200)

  @VaultRequest
  async def OnUnlock(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    if not pContext.Path in WebDav.Locks: return Response('Not Locked',404)
    WebDav.Locks.remove(pContext.Path)
    return Response('',204)

  @VaultRequest
  async def OnMkdir(pContext:Context):
    if not pContext.Vault.CreateDirectory(pContext.Path):
      return Response('Exists',409)
    return Response('Created',201)

  @VaultRequest
  async def OnPropGet(pContext:Context):
    def FormatTime(pWhat:float):
      return datetime.fromtimestamp(pWhat,tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z')
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    _Deep = request.headers.get('Depth','0')=='1'
    _Files = [pContext.Path]
    if _Deep: _Files.extend(pContext.Vault.ScanDir(pContext.Path))
    _Response = '<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">'
    for _File in _Files:
      if pContext.Vault.IsHidden(_File): continue
      _Info = pathlib.Path(pContext.Vault.GetFileName(_File))
      if _Info.is_dir():
        _Response += f'<D:response><D:href>/{WebDav.SanitizeXml(_File)}</D:href><D:propstat><D:prop><D:resourcetype><D:collection xmlns:D="DAV:"/></D:resourcetype><D:displayname>{WebDav.SanitizeXml(os.path.basename(_File))}</D:displayname><D:getlastmodified>{FormatTime(_Info.stat().st_mtime)}</D:getlastmodified><D:supportedlock><D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
      else:
        _Response += f'<D:response><D:href>/{WebDav.SanitizeXml(_File)}</D:href><D:propstat><D:prop><D:resourcetype></D:resourcetype><D:displayname>{WebDav.SanitizeXml(os.path.basename(_File))}</D:displayname><D:getcontentlength>{_Info.stat().st_size}</D:getcontentlength><D:creationdate>{FormatTime(_Info.stat().st_mtime)}</D:creationdate><D:getlastmodified>{FormatTime(_Info.stat().st_mtime)}</D:getlastmodified><D:supportedlock><D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
    _Response += '</D:multistatus>'
    return Response(_Response,200,content_type='application/xml; charset=utf-8')
    
  @VaultRequest
  async def OnPropSet(pContext:Context):
    if not pContext.Vault.Exists(pContext.Path): return pContext.NotFound
    _Body = request.data.decode('utf-8')
    _CreationTime = WebDav.GetRegexMatch('<Z:Win32CreationTime>(.*)</Z:Win32CreationTime>',_Body)
    _LastAccessTime = WebDav.GetRegexMatch('<Z:Win32LastAccessTime>(.*)</Z:Win32LastAccessTime>',_Body)
    _LastModifiedTime = WebDav.GetRegexMatch('<Z:Win32LastModifiedTime>(.*)</Z:Win32LastModifiedTime>',_Body)
    _FileAttributes = WebDav.GetRegexMatch('<Z:Win32FileAttributes>(.*)</Z:Win32FileAttributes>',_Body)

    #"application/xml; charset=utf-8"
    _Response = f'<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{WebDav.SanitizeXml(pContext.Path)}</D:href><D:propstat><D:prop>'
    _Patches = ''
    _Info = pathlib.Path(pContext.FileName)
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
    pContext.Vault.Update(pContext.Path,created=_CreationTime,accessed=_LastAccessTime,modified=_LastModifiedTime)
    return Response(_Response,200,content_type='application/xml; charset=utf-8')
