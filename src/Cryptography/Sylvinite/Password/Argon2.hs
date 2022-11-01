{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}

module Cryptography.Sylvinite.Password.Argon2 where

import qualified Data.Text as T
import qualified Data.ByteString as BS
import Cryptography.Sodium.Bindings.PasswordHashing
import System.IO.Unsafe

data ArgonParams = ArgonParams
  { outputLength :: Word64
  , opslimit     :: Word64
  , memlimit     :: Word64
  , algorithm    :: Algorithm
  }

hash :: ArgonParams -> Bytestring -> Bytestring ->  Maybe ByteString
hash ArgonParams{..} pass salt = unsafePerformIO $ do
  let alg = castAlgorithm algorithm
      outlen = fromIntegral outputLength
      action outPtr passwdPtr saltPtr = cryptoPWHash
        outPtr
        outlen
        passwdPtr
        passwdlen
        saltPtr
        opslimit
        memlimit
        alg
  allocaArray outlen $ \outPtr ->
    withArray (BS.unpack pass) $ \passwdPtr ->
      withArray (BS.unpack salt) $ \saltPtr -> do
        exitCode <- action outPtr passwdPtr saltPtr
        case fromEnum exitCode of
          0    -> do output <- peekArray outlen outPtr 
                     return $ (Just . BS.pack) output
          (-1) -> return Nothing
          _    -> return Nothing

{-
hashEncoded
verify
-}
data Algorithm = Default | Argon2I13 | Argon2ID13

castAlgorithm :: Algorithm -> CInt
castAlgorithm = \case 
  Default    -> cryptoPWHashAlgDefault
  Argon2I13  -> cryptoPWHashAlgArgon2I13
  Argon2ID13 -> cryptoPWHashAlgArgon2ID13
