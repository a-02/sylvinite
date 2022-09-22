module Cryptography.Sylvinite (getRandomBytes) where

import Cryptography.Sodium.Bindings.Random
import Data.ByteString
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

-- | Generate an amount of random bytes.
-- In `cryptonite`, IO and ByteString are replaced with the typeclasses 
-- "MonadRandom" and "ByteArray" from the `cryptonite` and `memory` libraries
-- respectively. For noe, these have been eliminated to their most common 
-- instances.
getRandomBytes :: Int -> IO ByteString
getRandomBytes bytes = do
  firstPtr <- mallocBytes bytes
  randombytesBuf firstPtr (toEnum bytes)
  let arrayFunctions = (plusPtr firstPtr) <$> [0..bytes]
  result <- sequence $ peek <$> arrayFunctions
  sequence_ $ free <$> arrayFunctions
  return $ pack result
      
