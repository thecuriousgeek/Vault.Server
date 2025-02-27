from abc import ABC,abstractmethod
import hashlib
import Crypto
import Crypto.Cipher.DES
import Crypto.Util.Padding
import io

import Crypto.Cipher
import Crypto.Cipher.AES

class Hash:
  def Get(pWhat:str|bytearray):
    if isinstance(pWhat,str):
      return hashlib.sha256(pWhat.encode('utf-8')).digest().hex().lower()
    return hashlib.sha256(pWhat).digest()

class AbstractCrypt(ABC):
  @abstractmethod
  def EncryptStream(self,pWhat)->io.BytesIO: pass    
  def Encrypt(self,pWhat)->str|bytes:
    if isinstance(pWhat,str):
      return self.Encrypt(pWhat.encode('utf-8')).hex().lower()
    elif isinstance(pWhat,bytes):
      _In = io.BytesIO(pWhat)
      _Out = io.BytesIO()
      for r in self.EncryptStream(_In):
        _Out.write(r)
      return _Out.getvalue()
    raise Exception('Invalid type')
  @abstractmethod
  def DecryptStream(self,pWhat)->io.BytesIO: pass    
  def Decrypt(self,pWhat)->str|bytes:
    if isinstance(pWhat,str):
      return self.Decrypt(bytes.fromhex(pWhat.lower())).decode('utf-8')
    elif isinstance(pWhat,bytes):
      _In = io.BytesIO(pWhat)
      _Out = io.BytesIO()
      for r in self.DecryptStream(_In):
        _Out.write(r)
      return _Out.getvalue()
    raise Exception('Invalid type')

class AES(AbstractCrypt):
  def __init__(self,pKey:bytes|str):
    self.Key = Hash.Get(pKey.encode('utf-8'))[0:32] if isinstance(pKey,str) else pKey[0:32]
    self.IV = self.Key[0:16]
    
  def EncryptStream(self,pWhat):
    if not (hasattr(pWhat, 'read') and callable(pWhat.read)): raise Exception('Invalid stream to encrypt')
    _Crypto = Crypto.Cipher.AES.new(self.Key,Crypto.Cipher.AES.MODE_CBC,iv=self.IV)
    while True:
      _Buff = pWhat.read(Crypto.Cipher.AES.block_size*1024)
      if len(_Buff)==0: return
      # if pWhat.tell()==pWhat.getbuffer().nbytes:
      if len(_Buff)<Crypto.Cipher.AES.block_size*1024:
        _Buff = Crypto.Util.Padding.pad(_Buff,Crypto.Cipher.AES.block_size,style='pkcs7')
      _Out = _Crypto.encrypt(_Buff)
      yield _Out
  
  def DecryptStream(self, pWhat):
    if not (hasattr(pWhat, 'read') and callable(pWhat.read)): raise Exception('Invalid stream to decrypt')
    _Crypto = Crypto.Cipher.AES.new(self.Key,Crypto.Cipher.AES.MODE_CBC,iv=self.IV)
    while True:
      _Buff = pWhat.read(Crypto.Cipher.AES.block_size*1024)
      if len(_Buff)==0: return
      _Out = _Crypto.decrypt(_Buff)
      # if pWhat.tell()==pWhat.getbuffer().nbytes:
      if len(_Buff)<Crypto.Cipher.AES.block_size*1024:
        yield Crypto.Util.Padding.unpad(_Out,Crypto.Cipher.AES.block_size,style='pkcs7')
      else: yield _Out
  
class DES(AbstractCrypt):
  def __init__(self,pKey:bytes|str):
    if isinstance(pKey,str): pKey = Hash.Get(pKey.encode('utf-8'))
    self.Key = Hash.Get(pKey.encode('utf-8'))[0:8] if isinstance(pKey,str) else pKey[0:8]
    self.IV = self.Key[0:8]
    
  def EncryptStream(self,pWhat):
    if not (hasattr(pWhat, 'read') and callable(pWhat.read)): raise Exception('Invalid stream to encrypt')
    _Crypto = Crypto.Cipher.DES.new(self.Key,Crypto.Cipher.DES.MODE_CBC,iv=self.IV)
    while True:
      _Buff = pWhat.read(Crypto.Cipher.DES.block_size*1024)
      if len(_Buff)==0: return
      # if pWhat.tell()==pWhat.getbuffer().nbytes:
      if len(_Buff)<Crypto.Cipher.AES.block_size*1024:
        _Buff = Crypto.Util.Padding.pad(_Buff,Crypto.Cipher.DES.block_size,style='pkcs7')
      _Out = _Crypto.encrypt(_Buff)
      yield _Out
  
  def DecryptStream(self, pWhat):
    if not (hasattr(pWhat, 'read') and callable(pWhat.read)): raise Exception('Invalid stream to decrypt')
    _Crypto = Crypto.Cipher.DES.new(self.Key,Crypto.Cipher.DES.MODE_CBC,iv=self.IV)
    while True:
      _Buff = pWhat.read(Crypto.Cipher.DES.block_size*1024)
      if len(_Buff)==0: return
      _Out = _Crypto.decrypt(_Buff)
      # if pWhat.tell()==pWhat.getbuffer().nbytes:
      if len(_Buff)<Crypto.Cipher.AES.block_size*1024:
        yield Crypto.Util.Padding.unpad(_Out,Crypto.Cipher.DES.block_size,style='pkcs7')
      else: yield _Out

def Test():
  k = "Test"
  h = Hash.Get(k)
  b = Hash.Get(k.encode('utf-8'))
  print(f"Hashed '{k}/{len(k)} to {len(b)} coded '{h}/{len(h)}")
  
  for c in [AES(k),DES(k)]:
    for s in ["1234","1234567","12345678","1234567890123456","12345678901234567890123456789012","slightly larger.txt", "This is a very long line that needs multiple blocks"]:
      e = c.Encrypt(s)
      d = c.Decrypt(e)
      print(f"Encrypted {s}/{len(s)} to {e}/{len(e)}")
      print(f"Decrypted {e}/{len(e)} to {d}/{len(d)}")
