import os
import pathlib
import dateutil
from LibPython import Logger
import Crypt

class Config:
  #Class variables
  Instances:dict[str:str]={} #List of name/signature
  @staticmethod
  def Vaults(): return Config.Instances.keys()  
  def GetSignature(pPassword:str): return Crypt.AES(pPassword).Encrypt('vault') if pPassword else 'vault'
  #region class helper methods
  def Load():
    _Logger = Logger('Vault.Load')
    _Logger.Info(f'Loading vaults from {os.getcwd()}')
    for _Folder in os.scandir("."):
      if os.path.isfile(_Folder.path+'/.vault'):
        _Signature = open(_Folder.path+'/.vault').readline()
        _Name = _Folder.name
        Config.Instances[_Name] = _Signature
        _Logger.Info(f'Found {_Name}')
    _Logger.Info(f'Found {len(Config.Instances)} vaults')
  def Create(pName,pPassword)->bool:
    _Logger = Logger('Vault.Create')
    if os.path.exists(pName): return False
    os.makedirs(pName,exist_ok=False)
    _Signature = Config.GetSignature(pPassword)
    open(f'{pName}/.vault','w').write(_Signature)
    Config.Instances[pName] = _Signature
    _Logger.Info(f'{pName} Created')
    return True
  def Open(pName,pPassword):
    if not pName in Config.Vaults(): return None
    if not Config.Instances[pName].upper()==Config.GetSignature(pPassword).upper(): return None
    _Vault = Vault(pName,pPassword)
    return _Vault
  #endregion

class Vault:
  def Log(self,pWhat): self.Logger.Info(pWhat)
  def __init__(self,pName,pPassword):
    self.Name=pName
    self.Logger = Logger(f'Vault.{self.Name}')
    self.CryptoData = Crypt.AES(pPassword) if pPassword else None
    self.CryptoName = Crypt.DES(pPassword) if pPassword else None
  #region Helpers
  def EncryptPath(self,pPath:str)->str:
    if not self.CryptoName: return pPath
    _Result=[]
    for p in pPath.replace('\\','/').replace('//','/').split('/'):
      if p: _Result.append(self.CryptoName.Encrypt(p))
    return '/'+'/'.join(_Result) 
  def DecryptPath(self,pPath:str)->str:
    if not self.CryptoName: return pPath
    _Result=[]
    for p in pPath.replace('\\','/').replace('//','/').split('/'):
      if p: _Result.append(self.CryptoName.Decrypt(p))
    return '/'+'/'.join(_Result)    
  def GetFileName(self,pPath:str)->str:
    return f'{self.Name}/{self.EncryptPath(pPath)}'.replace('\\','/').replace('//','/')
  def GetPath(self,pFileName:str)->str:
    return self.DecryptPath(pFileName[len(self.Name):]).replace('\\','/').replace('//','/')
  def IsHidden(self,pPath:str)->bool:
    return pPath=='/.vault'
  #endregion
  #region Operations
  def CopyFrom(self,pPath:str):
    try:
      if self.CryptoData:
        with open(self.GetFileName(pPath),'rb') as _File:
          for _Buff in  self.CryptoData.DecryptStream(_File):
            yield _Buff
      else:
        with open(self.GetFileName(pPath),'rb') as _File:
          while True:
            _Buff = _File.read(1024)
            if not _Buff: return
            yield _Buff
    except:
      pass
  def CopyTo(self,pPath:str,pStream):
    if self.CryptoData:
      with open(self.GetFileName(pPath),'wb') as _File:
        for _Buff in  self.CryptoData.EncryptStream(pStream):
          _File.write(_Buff)
    else:
      with open(self.GetFileName(pPath),'wb') as _File:
        while True:
          _Buff = pStream.read(1024)
          if not _Buff: return
          _File.write(_Buff)
  def Delete(self,pPath:str)->bool:
    if os.path.isfile(self.GetFileName(pPath)):
      os.unlink(self.GetFileName(pPath))
    else:
      os.rmdir(self.GetFileName(pPath))  
  def Move(self,pSrc:str,pDst:str)->bool:
    if not os.path.exists(self.GetFileName(pSrc)) or os.path.exists(self.GetFileName(pDst)): return False
    os.rename(self.GetFileName(pSrc),self.GetFileName(pDst))
    return True  
  def CreateDirectory(self,pPath:str)->bool:
    if os.path.exists(self.GetFileName(pPath)): return False
    os.makedirs(self.GetFileName(pPath),True)
    return True
  def Exists(self,pPath)->bool:
    if pPath=='/': return True
    return os.path.exists(self.GetFileName(pPath))
  def oScanDir(self,pPath)->list:
    _Folder = self.GetFileName(pPath)
    if os.path.isfile(_Folder): return pPath
    _Files = [x.path.replace('\\','/').replace('//','/') for x in os.scandir(_Folder)] 
    return sorted([self.GetPath(x) for x in _Files if not x.endswith('/.vault')])
  def ScanDir(self,pPath, pDepth):
    _Result = ['/']
    _Folder = self.GetFileName(pPath)
    if os.path.isfile(_Folder): return pPath
    if _Folder[-1]=='/': _Folder = _Folder[:-1] 
    _Depth = _Folder.count('/') + pDepth
    for r, d, f in os.walk(_Folder):
      r = r.replace('\\','/').replace('//','/')
      if r.count('/')>_Depth-1: break
      for n in d:
        _Result.append(r+'/'+n+'/')
      for n in f:
        fn=r+'/'+n
        if fn.count('/')>_Depth: break
        _Result.append(fn)
    return sorted([self.GetPath(x).replace('\\','/').replace('//','/') for x in _Result if not x.endswith('/.vault')])
  def Update(self,pPath:str,created=None,accessed=None,modified=None):
    _Info = pathlib.Path(self.GetFileName(pPath))
    _Modified = dateutil.parser.parse(modified).timestamp() if modified else _Info.stat().st_mtime
    _Accessed = dateutil.parser.parse(accessed).timestamp() if accessed else _Info.stat().st_atime
    os.utime(self.GetFileName(pPath),(_Accessed,_Modified))
    