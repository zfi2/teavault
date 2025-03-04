## teavault - a header-only compile-time string encryption functionality using the tiny encryption algorithm (tea).

## features
- compile-time encryption to resist reverse-engineering
- automatic or manual decryption at runtime
- order scrambling for additional obfuscation
- flexible key generation with optional custom seeds

## how it works
the encryption uses the tea algorithm with a 128-bit key. by default, the key is generated using `__TIME__` and `__DATE__` preprocessor macros, ensuring a unique key for each compilation. you can also provide custom seed values to generate the key.

## example usage
```cpp
#include <iostream>
#include "tea_str.hpp"

int main() {
    // automatic decryption with default key generation
    auto decrypted_str = tea_str("automatically decrypted string!");

    // manual decryption object
    auto encrypted_obj = tea_str_m("manually decrypted string");

    // custom seed key generation
    auto custom_seed_str = tea_str("custom seed example", 1234, 5678, 91011, 1213);

    std::cout << "automatic decryption: " << decrypted_str << "\n";
    std::cout << "manual decryption: " << encrypted_obj.decrypt() << "\n";
    std::cout << "custom seed decryption: " << custom_seed_str << "\n";

    return 0;
}
```

## macro references
- `tea_str(str, ...)`: creates encrypted string with automatic decryption
  - `str`: string to encrypt
  - `...`: optional custom seed values

- `tea_str_m(str, ...)`: creates encrypted string object for manual decryption
  - `str`: string to encrypt
  - `...`: optional custom seed values

## key generation
the `key_generator::generate()` method creates a 128-bit key from:
- default: `__TIME__` and `__DATE__` preprocessor macros
- custom: user-provided seed values

## license
this project is licensed under the MIT license. see the [LICENSE](LICENSE) file for details.
