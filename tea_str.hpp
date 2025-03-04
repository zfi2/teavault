#ifndef TEA_STR_HPP
#define TEA_STR_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace tea {
    // tea constants
    constexpr uint32_t DELTA = 0x9e3779b9u;
    constexpr size_t ROUNDS = 64;

    // generates a 128-bit key from provided values (defaults to time/date)
    class key_generator {
    public:
        template <typename... Args>
        static constexpr std::array<uint32_t, 4> generate(Args... seed) {
            std::array<uint32_t, 4> key = { static_cast<uint32_t>(seed)... };
            return { key[2], key[0], key[3], key[1] };
        }
    };

    // tea cipher implementation
    class cipher {
    public:
        // encrypts a 64-bit block
        static constexpr uint64_t encrypt_block(uint32_t v0, uint32_t v1, const std::array<uint32_t, 4>& key) {
            uint32_t sum = 0;
            for (size_t i = 0; i < ROUNDS; ++i) {
                sum += DELTA;
                v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
                v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
            }
            return (static_cast<uint64_t>(v0) << 32) | v1;
        }

        // decrypts a 64-bit block
        static constexpr uint64_t decrypt_block(uint32_t v0, uint32_t v1, const std::array<uint32_t, 4>& key) {
            uint32_t sum = static_cast<uint32_t>(DELTA * ROUNDS);
            for (size_t i = 0; i < ROUNDS; ++i) {
                v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
                v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
                sum -= DELTA;
            }
            return (static_cast<uint64_t>(v0) << 32) | v1;
        }
    };

    // compile-time encrypted string class
    template <size_t N, uint32_t S1 = __TIME__[0], uint32_t S2 = __TIME__[1], uint32_t S3 = __DATE__[0], uint32_t S4 = __DATE__[1]>
    class encrypted_string {
        std::array<uint64_t, (N + 7) / 8> encrypted; // stores encrypted 64-bit blocks
        static constexpr auto key = key_generator::generate(S1, S2, S3, S4); // compile-time key

    public:
        // constructor: encrypts the string at compile-time
        constexpr encrypted_string(const char(&str)[N]) : encrypted{} {
            for (size_t i = 0; i < encrypted.size(); ++i) {
                size_t idx = (i * 5) % encrypted.size(); // scramble order
                uint32_t part1 = 0, part2 = 0;
                size_t offset = idx * 8;

                for (size_t j = 0; j < 4; ++j) {
                    size_t pos = offset + j;
                    part1 |= (pos < N - 1 ? static_cast<uint32_t>(str[pos]) : 0u) << (j * 8);
                }
                for (size_t j = 0; j < 4; ++j) {
                    size_t pos = offset + 4 + j;
                    part2 |= (pos < N - 1 ? static_cast<uint32_t>(str[pos]) : 0u) << (j * 8);
                }
                encrypted[idx] = cipher::encrypt_block(part1, part2, key);
            }
        }

        // decrypts and returns the original string
        const char* decrypt() const {
            static thread_local char decrypted[N]{};
            for (size_t i = 0; i < encrypted.size(); ++i) {
                size_t idx = (i * 5) % encrypted.size();
                uint64_t block = encrypted[idx];
                uint32_t v0 = static_cast<uint32_t>(block >> 32);
                uint32_t v1 = static_cast<uint32_t>(block & 0xFFFFFFFFu);
                uint64_t plain = cipher::decrypt_block(v0, v1, key);
                v0 = static_cast<uint32_t>(plain >> 32);
                v1 = static_cast<uint32_t>(plain & 0xFFFFFFFFu);

                size_t offset = idx * 8;
                for (size_t j = 0; j < 4; ++j) {
                    if (offset + j < N - 1)
                        decrypted[offset + j] = static_cast<char>((v0 >> (j * 8)) & 0xFFu);
                }
                for (size_t j = 0; j < 4; ++j) {
                    if (offset + 4 + j < N - 1)
                        decrypted[offset + 4 + j] = static_cast<char>((v1 >> (j * 8)) & 0xFFu);
                }
            }
            decrypted[N - 1] = '\0';
            return decrypted;
        }
    };
}

// macro for automatic decryption
#define tea_str(str, ...) ([]{ \
    static constexpr tea::encrypted_string<sizeof(str), ##__VA_ARGS__> encrypted_str(str); \
    return encrypted_str.decrypt(); \
}())

// macro for manual decryption
#define tea_str_m(str, ...) ([]{ \
    static constexpr tea::encrypted_string<sizeof(str), ##__VA_ARGS__> encrypted_str(str); \
    return encrypted_str; \
}())

#endif // TEA_STR_HPP
