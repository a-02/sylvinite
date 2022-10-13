module Cryptography.Sylvinite.Random (getRandomBytes) where

import Cryptography.Sodium.Bindings.Random
import Data.ByteString
import Foreign.Marshal.Array

-- | Generate an amount of random bytes.
-- In `cryptonite`, IO and ByteString are replaced with the typeclasses 
-- "MonadRandom" and "ByteArray" from the `cryptonite` and `memory` libraries
-- respectively. For noe, these have been eliminated to their most common 
-- instances.
getRandomBytes :: Int -> IO ByteString
getRandomBytes bytes = do
  ptr <- mallocArray bytes
  randombytesBuf ptr (toEnum bytes)
  result <- peekArray bytes ptr
  return $ pack result
      
