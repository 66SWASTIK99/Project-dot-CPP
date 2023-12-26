#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

// MD5 constants
const uint32_t MD5_A = 0x67452301;
const uint32_t MD5_B = 0xEFCDAB89;
const uint32_t MD5_C = 0x98BADCFE;
const uint32_t MD5_D = 0x10325476;

// Shift amounts for each round
const int S[] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };

// Constants for each round
const uint32_t T[] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

// Helper function for converting a 64-bit integer to big-endian
uint64_t htobe64(uint64_t value) {
    return ((value & 0xFF00000000000000ull) >> 56) |
           ((value & 0x00FF000000000000ull) >> 40) |
           ((value & 0x0000FF0000000000ull) >> 24) |
           ((value & 0x000000FF00000000ull) >> 8) |
           ((value & 0x00000000FF000000ull) << 8) |
           ((value & 0x0000000000FF0000ull) << 24) |
           ((value & 0x000000000000FF00ull) << 40) |
           ((value & 0x00000000000000FFull) << 56);
}

// Helper functions
inline uint32_t F(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y) | (~X & Z); }
inline uint32_t G(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Z) | (Y & ~Z); }
inline uint32_t H(uint32_t X, uint32_t Y, uint32_t Z) { return X ^ Y ^ Z; }
inline uint32_t I(uint32_t X, uint32_t Y, uint32_t Z) { return Y ^ (X | ~Z); }

// Rotate left operation
inline uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// MD5 transformation
void md5_transform(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, const uint32_t* M) {
    for (int i = 0; i < 64; ++i) {
        uint32_t X, g;
        if (i < 16) {
            X = F(B, C, D);
            g = i;
        } else if (i < 32) {
            X = G(B, C, D);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            X = H(B, C, D);
            g = (3 * i + 5) % 16;
        } else {
            X = I(B, C, D);
            g = (7 * i) % 16;
        }

        X = X + A + T[i] + M[g];
        A = D;
        D = C;
        C = B;
        B = B + rotate_left(X, S[i]);
    }
}

// Padding and MD5 calculation
std::string md5(const std::string& input) {
    uint64_t total_bits = input.length() * 8;
    uint32_t A = MD5_A, B = MD5_B, C = MD5_C, D = MD5_D;

    // Determine the size of the padding
    size_t initial_length = input.length();
    size_t padding_size = (initial_length % 64 < 56) ? (56 - initial_length % 64) : (120 - initial_length % 64);

    // Create a buffer for the padded message
    uint8_t paddedMessage[initial_length + padding_size + 8];

    // Copy the input to the buffer
    std::memcpy(paddedMessage, input.c_str(), initial_length);

    // Append the '1' bit
    paddedMessage[initial_length] = 0x80;

    // Pad with zeros
    std::memset(paddedMessage + initial_length + 1, 0, padding_size);

    // Append the total length in bits
    total_bits = htobe64(total_bits);
    std::memcpy(paddedMessage + initial_length + padding_size + 1, &total_bits, sizeof(total_bits));

    // Process the message in 512-bit blocks
    for (size_t i = 0; i < initial_length + padding_size + 8; i += 64) {
        const uint32_t* block = reinterpret_cast<const uint32_t*>(paddedMessage + i);
        md5_transform(A, B, C, D, block);
    }

    // Format the hash as a string
    std::stringstream md5string;
    md5string << std::hex << std::setfill('0') << std::setw(8) << A
              << std::hex << std::setfill('0') << std::setw(8) << B
              << std::hex << std::setfill('0') << std::setw(8) << C
              << std::hex << std::setfill('0') << std::setw(8) << D;

    return md5string.str();
}

int main() {
    std::string input;
    std::cout << "Enter the string to hash using MD5: ";
    std::getline(std::cin, input);

    std::string hashed = md5(input);
    std::cout << "MD5 Hash: " << hashed << std::endl;

    return 0;
}