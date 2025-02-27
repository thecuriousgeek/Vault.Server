import os
import pathlib
from typing import Self
from datetime import datetime
import dateutil
from LibPython import IniFile, Logger
import Crypt

class Vault:
  Folder=None
  Instances:list[Self]=[]
  def Get(pName:str)->Self: return next((x for x in Vault.Instances if x.Name==pName),None)

  def __init__(self,pName:str,pFolder:str):
    self.Name=pName
    self.Folder=pFolder
    self.CryptoData = None
    self.CryptoName = None
    self.Mounted = False
    self.LastUse = datetime.min
    self.Logger = Logger(f'Vault.{self.Name}')
    if not os.path.isfile(f'{self.Folder}/.vault'): raise Exception(f'Cannot open vault {self.Name}')
    Vault.Instances.append(self)
    self.Log('Configured')
    
  def Log(self,pWhat): self.Logger.Info(pWhat)
  
  def Validate(self,pPassword:str)->bool:
    if not os.path.isfile(f'{self.Folder}/.vault'): return False
    if pPassword is None: return False
    _VaultHash = open(f'{self.Folder}/.vault').readline()
    _InputHash = Crypt.Hash.Get(pPassword)
    return _VaultHash.upper()==_InputHash.upper()

  def Mount(self,pPassword:str):
    self.CryptoData = Crypt.AES(pPassword) if pPassword else None
    self.CryptoName = Crypt.DES(pPassword) if pPassword else None
    self.Mounted = self.Validate(pPassword)

  def Unmount(self):
    self.CryptoData = None
    self.CryptoName = None
    self.Mounted = False

  def EncryptPath(self,pPath:str)->str:
    if not self.CryptoName: return pPath
    _Result=[]
    for p in pPath.replace('\\','/').split('/'):
      if p: _Result.append(self.CryptoName.Encrypt(p))
    return '/'+'/'.join(_Result)
  
  def DecryptPath(self,pPath:str)->str:
    if not self.CryptoName: return pPath
    _Result=[]
    for p in pPath.replace('\\','/').split('/'):
      if p: _Result.append(self.CryptoName.Decrypt(p))
    return '/'+'/'.join(_Result)
    
  def GetFileName(self,pPath:str)->str:
    return (self.Folder+self.EncryptPath(pPath)).replace('\\','/')
  
  def GetPath(self,pFileName:str)->str:
    return self.DecryptPath(pFileName[len(self.Folder):]).replace('\\','/')
  
  def IsHidden(self,pPath:str)->bool:
    return pPath=='/.vault'
  
  def CopyFrom(self,pPath:str):
    if not self.Mounted: return
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

  def CopyTo(self,pPath:str,pStream):
    if not self.Mounted: return
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
    if not self.Mounted: return False
    if os.path.isfile(self.GetFileName(pPath)):
      os.unlink(self.GetFileName(pPath))
    else:
      os.rmdir(self.GetFileName(pPath))
  
  def Move(self,pSrc:str,pDst:str)->bool:
    if not self.Mounted: return False
    if not os.path.exists(self.GetFileName(pSrc)) or os.path.exists(self.GetFileName(pDst)): return False
    os.rename(self.GetFileName(pSrc),self.GetFileName(pDst))
    return True
  
  def CreateDirectory(self,pPath:str)->bool:
    if not self.Mounted: return False
    if os.path.exists(self.GetFileName(pPath)): return False
    os.makedirs(self.GetFileName(pPath),True)
    return True

  def Exists(self,pPath)->bool:
    if pPath=='/': return True
    if not self.Mounted: return False
    return os.path.exists(self.GetFileName(pPath))

  def ScanDir(self,pPath)->list:
    if not self.Mounted: return []
    _Folder = self.GetFileName(pPath)
    if os.path.isfile(_Folder): return pPath
    _Files = os.scandir(_Folder)
    return [self.GetPath(x.path) for x in _Files if not x.path.replace('\\','/').endswith('/.vault')]

  def Update(self,pPath:str,created=None,accessed=None,modified=None):
    _Info = pathlib.Path(self.GetFileName(pPath))
    _Modified = dateutil.parser.parse(modified).timestamp() if modified else _Info.stat().st_mtime
    _Accessed = dateutil.parser.parse(accessed).timestamp() if accessed else _Info.stat().st_atime
    os.utime(self.GetFileName(pPath),(_Accessed,_Modified))
    
#region Static Methods
  def Load():
    _Logger = Logger('Load')
    _Logger.Info(f'Loading vaults from {Vault.Folder}/Vault.ini')
    _IniFile = IniFile(f'{Vault.Folder}/Vault.ini')
    for _Name in _IniFile.GetKeys('Vault'):
      _Vault = Vault(_Name,_IniFile.Get('Vault',_Name))

  def Save():
    _IniFile = IniFile(f'{Vault.Folder}/Vault.ini')
    for _Vault in Vault.Instances:
      _IniFile.Add('Vault',_Vault.Name,_Vault.Folder)
    _IniFile.Save()
    
  def Create():
    _Name = ''
    while not _Name:
      _Name = input('Enter the name for this vault:')
      if Vault.Get(_Name):
        print(f'Vault {_Name} already exists')
        _Name=''
        continue
    _Folder = ''
    while not _Folder:
      _Folder = input(f'Enter the folder location for {_Name}:')
      if not os.path.exists(os.path.dirname(_Folder)):
        print(f'Folder {os.path.dirname(_Folder)} does not exist')
        _Folder=''
        continue
      if not os.path.exists(_Folder): break
      if not list(os.scandir(_Folder)): break
      if os.path.isfile(f'{_Folder}/.vault'):
        print(f'{_Folder} already contains a vault, you are trying to open it')
        break
      print(f'Folder {_Folder} already exists and doesnt contain a vault')
      _Folder=''
    os.makedirs(_Folder,exist_ok=True)
    _Password = input(f'Enter the password for {_Name}:')
    if not _Password: print(f'**Warning** Vault {_Name} will be unencrypted')
    if not os.path.isfile(f'{_Folder}/.vault'):
      with open(f'{_Folder}/.vault','w') as _Signature:
        _Signature.write(Crypt.Hash.Get(_Password))
    _Vault = Vault(_Name,_Folder)
    if not _Vault.Validate(_Password):
      print('Could not validate vault')
      return
    Vault.Save()
    print(f'Vault {_Name} created')
#endregion