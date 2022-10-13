{-# LANGUAGE OverloadedStrings, RecordWildCards, ScopedTypeVariables #-}

module Cryptography.Sylvinite.Replace.Scrypt where

-- This module is meant to replace most of
-- `scrypt`'s Crypto.Scrypt.

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import Cryptography.Sodium.Bindings.Scrypt
import Cryptography.Sylvinite.Random
import Cryptography.Sylvinite.Internal
import Foreign.C.Types
import Foreign.C.String
import Foreign.Marshal.Array
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr
import Foreign.Storable
import GHC.Prim
import System.IO.Unsafe
import Unsafe.Coerce -- not my fault

newtype Pass = Pass { getPass :: BS.ByteString } deriving (Show, Eq)
newtype EncryptedPass = EncryptedPass { getEncryptedPass  :: BS.ByteString } deriving (Show, Eq)
newtype Salt = Salt { getSalt :: BS.ByteString } deriving (Show, Eq)
newtype PassHash = PassHash { getHash :: BS.ByteString } deriving (Show, Eq)

type ScryptParams = Parameters

newSalt :: IO Salt
newSalt = Salt <$> getRandomBytes 32

defaultParams :: ScryptParams
defaultParams = Parameters 14 8 1 64

-- This needs to get implemented before anything else.
{-
scrypt :: ScryptParams -> Salt -> Pass -> PassHash
scrypt Parameters{..} (Salt salt_in) (Pass pass_in) =
  PassHash <$> unsafePerformIO $ do
    let (outlen :: CULLong) = toEnum outputLength 
     in cryptoPWHashScryptSals2018SHA256
          out
          outlen
          passwd
          passwdlen
          salt
          opslimit
          memlimit
-}

withScrypt :: Ptr CChar -> (Ptr CUChar -> IO b) -> IO b
withScrypt passwdPtr action = do
  let size = fromIntegral cryptoPWHashScryptSalsa2018SHA256BytesMin  
  allocaBytes size action

hashPassword :: CString -> IO b     
hashPassword passwd = do 
  let size = fromIntegral cryptoPWHashScryptSalsa2018SHA256PasswdMin
      hashAction keyPtr passwdPtr saltPtr = cryptoPWHashScryptSalsa2018SHA256 -- :)
        keyPtr
        (coerce cryptoPWHashScryptSalsa2018SHA256BytesMin)
        passwdPtr
        (unsafeCoerce cryptoPWHashScryptSalsa2018SHA256PasswdMin)
        saltPtr
        (coerce cryptoPWHashScryptSalsa2018SHA256OpsLimitMin)
        cryptoPWHashScryptSalsa2018SHA256MemLimitMin
         
  allocaBytes size (\passwdPtr -> do 
   poke passwdPtr passwd 
   withScrypt passwdPtr hashAction
  )

{- Questions yet to be answered:

Should `combine` and `separate` be implemented in terms of libsodium's password storage?

How about `verifyPass`?

-}

-- encryptPassIO'

-- verifyPass'
