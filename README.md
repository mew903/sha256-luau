Luau implementation of SHA256 hash

Usage:
```lua
sha256(input: string): (hash: string, timeElapsed: number)
```

Example:
```lua
local sha256 = require(game.ReplicatedStorage.SHA256)

print(sha256('SHA256')) --> b3abe5d8c69b38733ad57ea75e83bcae42bbbbac75e3a5445862ed2f8a2cd677   0.00000008335...
print(sha256('mew903')) --> 2e502fa17214e0c5fbae24fbad05bb2a52d78b27f6f90e08b2ba2731d5f09735   0.00000008127...
```

You can find the "original" here: https://github.com/MaHuJa/CC-scripts/blob/master/sha256.lua
