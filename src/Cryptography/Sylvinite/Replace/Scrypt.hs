{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CApiFFI #-}

module Cryptography.Sylvinite.Replace.Scrypt where

-- This module is meant to replace most of
-- `scrypt`'s Crypto.Scrypt.

import Control.Monad.Trans.Cont
import Cryptography.Sodium.Bindings.Scrypt
import Cryptography.Sylvinite.Random
import Cryptography.Sylvinite.Internal
import qualified Data.ByteString as BS
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Array
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe -- I know what I'm doing.

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
scrypt :: Salt -> Pass -> PassHash
scrypt' = scrypt defaultParams

scrypt :: ScryptParams -> Salt -> Pass -> PassHash
scrypt params salt passwd -- Arguments reverse for backwards compatibility.
  | (BS.length . getPass $ passwd) > (fromIntegral cryptoPWHashScryptSalsa2018SHA256PasswdMax) = error "Password longer than maximum length."
  | outputLength params > (fromIntegral cryptoPWHashScryptSalsa2018SHA256BytesMax) = error "Output longer than maximum length."
  | outputLength params < (fromIntegral cryptoPWHashScryptSalsa2018SHA256BytesMin) = error "Output shorter than minimum length."
  | (r params) * (p params) > 2^30 = error "r times p should be less than 2^30."
  -- its probably best to catch these errors before sodium.h
  | otherwise = unsafePerformIO $ hashPasswordLL passwd salt params

{- Why did I need this? 
withScrypt :: Ptr CChar -> (Ptr CUChar -> IO b) -> IO b
withScrypt passwdPtr action = do
  let size = fromIntegral cryptoPWHashScryptSalsa2018SHA256BytesMin  
  allocaBytes size action
-}

-- sizeOf is the correct way to turn a CSize into some usable value. i'm sure of it.
hashPasswordLL :: Pass -> Salt -> ScryptParams -> IO PassHash     
hashPasswordLL (Pass passwd) (Salt salt) Parameters{..} = do 
  let outlen = outputLength
      len = CSize . fromIntegral . sizeOf
      hashAction keyPtr passwdPtr saltPtr = cryptoPWHashScryptSalsa2018SHA256ll -- :)
        passwdPtr
        (len passwdPtr)
        saltPtr
        (len saltPtr)
        (fromIntegral $ 2^n)
        (fromIntegral r)
        (fromIntegral p)
        keyPtr
        (len keyPtr)        
  withArray (BS.unpack passwd) $ \passwdPtr -> 
    allocaArray outlen $ \keyPtr -> -- May need allocaArray0. See Scrypt Spec.
      withArray (BS.unpack salt) $ \saltPtr -> do 
        exitCode <- hashAction keyPtr passwdPtr saltPtr
        case fromEnum exitCode of 
          0    -> do key_ll <- peekArray outlen keyPtr 
                     return $ (PassHash . BS.pack) key_ll
          (-1) -> error "Returned -1. Not my fault."
          _    -> error "Scrypt hashing function returned unrecognized exit code."

foreign import capi "sodium.h crypto_pwhash_scryptsalsa208sha256_ll"
  cryptoPWHashScryptSalsa2018SHA256ll :: 
    -- | Pointer to password.
    Ptr Word8 ->
    -- | Password length.
    CSize ->
    -- | Pointer to salt.
    Ptr Word8 ->
    -- | Salt length.
    CSize ->
    -- | N
    Word64 ->
    -- | r
    Word32 ->
    -- | p
    Word32 ->
    -- | Pointer to output buffer.
    Ptr Word8 ->
    -- | Output buffer size.
    CSize ->
    -- | Exit code.
    IO CInt
    
{- Don't look here. It is shameful. 
  allocaBytes size $ 
   \passwdPtr -> do 
     poke passwdPtr passwd 
     allocaBytes outlen $
       \keyPtr -> do
         allocaBytes saltlen $
           \saltPtr -> do
              poke saltPtr salt 
              hashAction keyPtr passwdPtr saltPtr
-}

{- Questions yet to be answered:

Should `combine` and `separate` be implemented in terms of libsodium's password storage?

How about `verifyPass`?

-}

-- encryptPassIO'

-- verifyPass'
