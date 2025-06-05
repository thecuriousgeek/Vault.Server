import os
import pathlib
from datetime import datetime, timezone
import re
import urllib.parse
from flask import Response, request
import mimetypes
from Vault import Vault, Config

def SanitizeXml(pWhat: str): return pWhat.replace( '&', '&amp;').replace('<', '&lt;')
def FormatTime(pWhat: float): return datetime.fromtimestamp(pWhat, tz=timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
def FormatISOTime(pWhat: float): return datetime.fromtimestamp(pWhat, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def SplitURL(pURI: str) -> tuple:
  _Path = urllib.parse.unquote(urllib.parse.urlparse(pURI).path)
  if _Path[0]=='/': _Path = _Path[1:]
  _Parts = _Path.split('/', 1)
  return (_Parts[0] if len(_Parts) > 0 else None, f'/{_Parts[1]}' if len(_Parts) > 1 else '/')
def GetRegexMatch(pPattern: str, pString: str):
  _Matches = re.search(pPattern, pString)
  return _Matches.group(1) if _Matches else None
def NotFound(pVault:str,pPath:str): return Response(f'{pPath}-Not Found in {pVault}', 404)

Locks = []
class Dav:
  def OnOptions(pVault:Vault):
    _Headers = {}
    _Headers['Allow'] = 'OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND'
    _Headers["Dav"] = '1, 2'
    return Response('', 200, headers=_Headers)

  def OnHead(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    return Response('', 200,)

  def OnGet(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    return Response(pVault.CopyFrom(pPath), mimetype=mimetypes.guess_type(pPath)[0])

  def OnPut(pVault:Vault,pPath:str):
    pVault.CopyTo(pPath, request.stream)
    return Response('Created', 200)

  def OnDelete(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    pVault.Delete(pPath)
    return Response('Gone', 200)

  def OnMove(pVault:Vault,pPath:str, pTarget:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    _Target = SplitURL(pTarget)[1]
    pVault.Move(pPath, _Target)
    return Response('Done', 200)

  def OnLock(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    _Name = pVault.Name + '/' + pPath
    if _Name in Locks: return Response('Already Locked', 423)
    Locks.append(_Name)
    _Body = request.data.decode('utf-8')
    _User = GetRegexMatch('<d:owner><d:href>(.*)</d:href></d:owner>', _Body)
    _Token = datetime.now().timestamp()
    _Response = f'<?xml version="1.0" encoding="utf-8"?><d:prop xmlns:D="DAV:"><d:lockdiscovery><d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope><d:depth>infinity</d:depth><d:owner><d:href>{_User}</d:href></d:owner><d:timeout>Second-3600</d:timeout><d:locktoken><d:href>{_Token}</d:href></d:locktoken><d:lockroot><d:href>{SanitizeXml(pPath)}</d:href></d:lockroot></d:activelock></d:lockdiscovery></d:prop>'
    return Response(_Response, 200)

  def OnUnlock(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    _Name = pVault.Name + '/' + pPath
    if not _Name in Locks: return Response('Not Locked', 404)
    Locks.remove(_Name)
    return Response('', 204)

  def OnMkCol(pVault:Vault,pPath:str):
    if not pVault.CreateDirectory(pPath): return Response('Exists', 409)
    return Response('Created', 201)

  def OnPropFind(pVault:Vault,pPath:str):
    if os.path.basename(pPath).startswith('.'): return NotFound(pVault.Name,pPath)  # Ignore hidden files, specially for mac metadata
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    _Depth = int(request.headers.get('Depth', '0'))
    _Files = pVault.ScanDir(pPath,_Depth) if _Depth else [pPath]
    _Response = '<?xml version="1.0" encoding="UTF-8"?><d:multistatus xmlns:d="DAV:">'
    for _File in _Files:
      if pVault.IsHidden(_File): continue
      # if os.path.basename(_File).startswith('.'): continue
      _Info = pathlib.Path(pVault.GetFileName(_File))
      _Response += f'<d:response><d:href>{SanitizeXml("/"+pVault.Name+_File)}</d:href><d:propstat><d:prop>'
      _Response += f'<d:displayname>{SanitizeXml(os.path.basename(_File) or os.path.basename(os.path.dirname(_File)))}</d:displayname>'
      _Response += f'<d:supportedlock><d:lockentry><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry></d:supportedlock>'
      _Response += f'<d:getlastmodified>{FormatTime(_Info.stat().st_mtime)}</d:getlastmodified>'
      if _Info.is_dir():
        _Response += f'<d:resourcetype><d:collection xmlns:d="DAV:"/></d:resourcetype>'
      else:
        _Response += f'<d:resourcetype/>'
        _Response += f'<d:getcontenttype>{mimetypes.guess_type(_File)[0] or "application/octet-stream"}</d:getcontenttype>'
        _Response += f'<d:getcontentlength>{_Info.stat().st_size}</d:getcontentlength>'
        _Response += f'<d:creationdate>{FormatISOTime(_Info.stat().st_mtime)}</d:creationdate>'
      _Response += f'</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'
    _Response += '</d:multistatus>'
    return Response(_Response, 207, content_type='application/xml; charset=utf-8')

  def OnPropPatch(pVault:Vault,pPath:str):
    if not pVault.Exists(pPath): return NotFound(pVault.Name,pPath)
    _Body = request.data.decode('utf-8')
    _CreationTime = GetRegexMatch('<Z:Win32CreationTime>(.*)</Z:Win32CreationTime>', _Body)
    _LastAccessTime = GetRegexMatch('<Z:Win32LastAccessTime>(.*)</Z:Win32LastAccessTime>', _Body)
    _LastModifiedTime = GetRegexMatch('<Z:Win32LastModifiedTime>(.*)</Z:Win32LastModifiedTime>', _Body)
    _FileAttributes = GetRegexMatch('<Z:Win32FileAttributes>(.*)</Z:Win32FileAttributes>', _Body)

    # "application/xml; charset=utf-8"
    _Response = f'<?xml version="1.0" encoding="UTF-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>{SanitizeXml(pPath)}</d:href><d:propstat><d:prop>'
    _Patches = ''
    _Info = pathlib.Path(pVault.GetFileName(pPath))
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
    _Response += '</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>'
    pVault.Update(pPath, created=_CreationTime,accessed=_LastAccessTime, modified=_LastModifiedTime)
    return Response(_Response, 200, content_type='application/xml; charset=utf-8')
