#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <filesystem>
#include <utility>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

// Constants for file format nd streaming
constexpr char MAGIC_BYTES[6] = {'F', 'C', 'R', 'Y', 'P', 'T'};
constexpr unsigned char FORMAT_VERSION = 0x01;
constexpr size_t CHUNK_SIZE = 64 * 1024; // chunks (64KB)

// RAII wrapper (locks RAM to prevent swap, zeroes on destruct)
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : data_(size, 0) {
        if (!data_.empty()) {
            sodium_mlock(data_.data(), data_.size());
        }
    }

    ~SecureBuffer() {
        clear();
    }

    // Delete copy op to prevent duplicating secret bytes in RAM
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Enable move op to transfer ownership safely without copying
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }

private:
    void clear() {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
            sodium_munlock(data_.data(), data_.size());
            data_.clear();
        }
    }

    std::vector<unsigned char> data_;
};

// RAII guard , disable terminal echo and guarantee restoration on exit/exception
class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
#ifdef _WIN32
        hStdin_ = GetStdHandle(STD_INPUT_HANDLE);
        if (GetConsoleMode(hStdin_, &oldMode_)) {
            active_ = true;
            SetConsoleMode(hStdin_, oldMode_ & (~ENABLE_ECHO_INPUT));
        }
#else
        if (tcgetattr(STDIN_FILENO, &oldt_) == 0) {
            active_ = true;
            termios newt = oldt_;
            newt.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
#endif
    }

    ~TerminalEchoGuard() {
        if (!active_) return;
#ifdef _WIN32
        SetConsoleMode(hStdin_, oldMode_);
#else
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt_);
#endif
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

private:
    bool active_ = false;
#ifdef _WIN32
    HANDLE hStdin_ = INVALID_HANDLE_VALUE;
    DWORD oldMode_ = 0;
#else
    termios oldt_{};
#endif
};

// Cross-platform passkey prompt (masked)
SecureBuffer promptPasskey(const std::string& promptText) {
    std::cout << promptText << std::flush;

    SecureBuffer buffer(256);
    size_t len = 0;

    {
        TerminalEchoGuard echoGuard;
        char ch = 0;
        while (std::cin.get(ch) && ch != '\n' && ch != '\r') {
            if (len < buffer.size() - 1) {
                buffer.data()[len++] = static_cast<unsigned char>(ch);
            }
        }
        sodium_memzero(&ch, sizeof(ch));
    }

    std::cout << "\n";

    if (len == 0) {
        throw std::runtime_error("Passkey cannot be empty.");
    }

    SecureBuffer exactPasskey(len);
    std::memcpy(exactPasskey.data(), buffer.data(), len);
    return exactPasskey;
}

// Derive a 256-bit stream key using argon2id (moderate)
SecureBuffer deriveKey(const SecureBuffer& passkey, const unsigned char* salt) {
    SecureBuffer key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    if (crypto_pwhash(key.data(), key.size(),
                      reinterpret_cast<const char*>(passkey.data()), passkey.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Key derivation failed (insufficient memory).");
    }
    return key;
}

void encryptFile(const fs::path& inPath, const fs::path& outPath, const SecureBuffer& passkey) {
    if (!fs::exists(inPath) || !fs::is_regular_file(inPath)) {
        throw std::runtime_error("Input file does not exist or is not a regular file.");
    }
    if (fs::exists(outPath)) {
        throw std::runtime_error("Output file already exists. Refusing to overwrite.");
    }

    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Failed to open input file.");
    }

    fs::path tempPath = outPath;
    tempPath += ".tmp";

    try {
        std::ofstream outFile(tempPath, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            throw std::runtime_error("Failed to create temporary output file.");
        }

        // Generate Salt and derive key
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));
        SecureBuffer key = deriveKey(passkey, salt);

        // Initialize secretstream push state and header
        crypto_secretstream_xchacha20poly1305_state state;
        unsigned char streamHeader[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        if (crypto_secretstream_xchacha20poly1305_init_push(&state, streamHeader, key.data()) != 0) {
            throw std::runtime_error("Failed to initialize encryption stream.");
        }

        /* -*- Construct & write file header -*-
        [MAGIC (6B)] + [VERSION (1B)] + [SALT (16B)] + [STREAM_HEADER (24B)] 
        */
        std::vector<unsigned char> fileHeader;
        fileHeader.insert(fileHeader.end(), MAGIC_BYTES, MAGIC_BYTES + sizeof(MAGIC_BYTES));
        fileHeader.push_back(FORMAT_VERSION);
        fileHeader.insert(fileHeader.end(), salt, salt + sizeof(salt));
        fileHeader.insert(fileHeader.end(), streamHeader, streamHeader + sizeof(streamHeader));

        outFile.write(reinterpret_cast<const char*>(fileHeader.data()),
                      static_cast<std::streamsize>(fileHeader.size()));

        // Stream file in 64 KB chunks
        std::vector<unsigned char> inBuf(CHUNK_SIZE);
        std::vector<unsigned char> outBuf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
        bool isFirstChunk = true;

        while (true) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()),
                        static_cast<std::streamsize>(inBuf.size()));
            std::streamsize bytesRead = inFile.gcount();
            bool eof = inFile.eof();

            unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
            unsigned long long outLen = 0;

            // Bind the unencrypted fileHeader as AAD on the first chunk to detect header tampering
            const unsigned char* aad = isFirstChunk ? fileHeader.data() : nullptr;
            size_t aadLen = isFirstChunk ? fileHeader.size() : 0;
            isFirstChunk = false;

            if (crypto_secretstream_xchacha20poly1305_push(
                    &state, outBuf.data(), &outLen,
                    inBuf.data(), static_cast<unsigned long long>(bytesRead),
                    aad, aadLen, tag) != 0) {
                throw std::runtime_error("Encryption error occurred during streaming.");
            }

            outFile.write(reinterpret_cast<const char*>(outBuf.data()),
                          static_cast<std::streamsize>(outLen));
            if (!outFile.good()) {
                throw std::runtime_error("Disk write error occurred.");
            }

            if (eof) break;
        }

        outFile.flush();
        if (!outFile.good()) {
            throw std::runtime_error("Failed to flush output file.");
        }
        outFile.close();
        inFile.close();

        // Atomically move temp file to final dest
        fs::rename(tempPath, outPath);
        std::cout << "Encrypted successfully -> " << outPath.string() << "\n";

    } catch (...) {
        if (fs::exists(tempPath)) {
            fs::remove(tempPath);
        }
        throw;
    }
}

void decryptFile(const fs::path& inPath, const fs::path& outPath, const SecureBuffer& passkey) {
    if (!fs::exists(inPath) || !fs::is_regular_file(inPath)) {
        throw std::runtime_error("Input file does not exist or is not a regular file.");
    }
    if (fs::exists(outPath)) {
        throw std::runtime_error("Output file already exists. Refusing to overwrite.");
    }

    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Failed to open input file.");
    }

    // Read and validate file header
    constexpr size_t headerSize = sizeof(MAGIC_BYTES) + 1 + crypto_pwhash_SALTBYTES + crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    std::vector<unsigned char> fileHeader(headerSize);
    inFile.read(reinterpret_cast<char*>(fileHeader.data()),
                static_cast<std::streamsize>(fileHeader.size()));

    if (static_cast<size_t>(inFile.gcount()) < headerSize ||
        std::memcmp(fileHeader.data(), MAGIC_BYTES, sizeof(MAGIC_BYTES)) != 0) {
        throw std::runtime_error("Invalid file format (not a valid FCRYPT archive).");
    }

    if (fileHeader[sizeof(MAGIC_BYTES)] != FORMAT_VERSION) {
        throw std::runtime_error("Unsupported file format version.");
    }

    const unsigned char* salt = fileHeader.data() + sizeof(MAGIC_BYTES) + 1;
    const unsigned char* streamHeader = salt + crypto_pwhash_SALTBYTES;

    // Derive key and initialize pull stream
    SecureBuffer key = deriveKey(passkey, salt);
    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, streamHeader, key.data()) != 0) {
        throw std::runtime_error("Corrupted stream header.");
    }

    fs::path tempPath = outPath;
    tempPath += ".tmp";

    try {
        std::ofstream outFile(tempPath, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            throw std::runtime_error("Failed to create temporary output file.");
        }

        // Read and decrypt chunks
        std::vector<unsigned char> inBuf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
        std::vector<unsigned char> outBuf(CHUNK_SIZE);
        bool isFirstChunk = true;
        bool foundFinalTag = false;

        while (true) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()),
                        static_cast<std::streamsize>(inBuf.size()));
            std::streamsize bytesRead = inFile.gcount();

            if (bytesRead == 0) {
                if (!foundFinalTag) {
                    throw std::runtime_error("File is truncated (missing final authentication tag).");
                }
                break;
            }

            unsigned long long outLen = 0;
            unsigned char tag = 0;

            const unsigned char* aad = isFirstChunk ? fileHeader.data() : nullptr;
            size_t aadLen = isFirstChunk ? fileHeader.size() : 0;
            isFirstChunk = false;

            if (crypto_secretstream_xchacha20poly1305_pull(
                    &state, outBuf.data(), &outLen, &tag,
                    inBuf.data(), static_cast<unsigned long long>(bytesRead),
                    aad, aadLen) != 0) {
                throw std::runtime_error("Decryption failed! Wrong passkey or corrupted/tampered file.");
            }

            outFile.write(reinterpret_cast<const char*>(outBuf.data()),
                          static_cast<std::streamsize>(outLen));
            if (!outFile.good()) {
                throw std::runtime_error("Disk write error occurred.");
            }

            if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                foundFinalTag = true;
                // Ensure no trailing garbage exists after the final authenticated chunk
                if (inFile.peek() != std::ifstream::traits_type::eof()) {
                    throw std::runtime_error("Trailing data detected after end of encrypted stream.");
                }
                break;
            }
        }

        outFile.flush();
        if (!outFile.good()) {
            throw std::runtime_error("Failed to flush output file.");
        }
        outFile.close();
        inFile.close();

        // Atomically move temp file to final destination
        fs::rename(tempPath, outPath);
        std::cout << "Decrypted successfully -> " << outPath.string() << "\n";

    } catch (...) {
        if (fs::exists(tempPath)) {
            fs::remove(tempPath);
        }
        throw;
    }
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Fatal: Failed to initialize libsodium.\n";
        return 1;
    }

    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input_file> <output_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    fs::path inFile = argv[2];
    fs::path outFile = argv[3];

    try {
        if (mode == "encrypt") {
            SecureBuffer pass1 = promptPasskey("Enter passkey: ");
            SecureBuffer pass2 = promptPasskey("Confirm passkey: ");

            if (pass1.size() != pass2.size() ||
                sodium_memcmp(pass1.data(), pass2.data(), pass1.size()) != 0) {
                throw std::runtime_error("Passkeys do not match.");
            }

            encryptFile(inFile, outFile, pass1);

        } else if (mode == "decrypt") {
            SecureBuffer passkey = promptPasskey("Enter passkey: ");
            decryptFile(inFile, outFile, passkey);

        } else {
            std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
