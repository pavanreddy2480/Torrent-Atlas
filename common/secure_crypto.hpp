#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

class Sha256 {
    std::uint32_t state_[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    std::uint64_t bytes_ = 0;
    unsigned char buffer_[64]{};
    std::size_t buffered_ = 0;

    static std::uint32_t rotate(std::uint32_t value, unsigned amount) {
        return (value >> amount) | (value << (32U - amount));
    }

    void transform(const unsigned char block[64]) {
        static const std::uint32_t constants[64] = {
            0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
            0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
            0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
            0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
            0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
            0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
            0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
            0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
        };
        std::uint32_t words[64];
        for (int i = 0; i < 16; ++i)
            words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24U) |
                       (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U) |
                       (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U) |
                       static_cast<std::uint32_t>(block[i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3U);
            std::uint32_t s1 = rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10U);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        std::uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t s1=rotate(e,6)^rotate(e,11)^rotate(e,25);
            std::uint32_t choose=(e&f)^((~e)&g);
            std::uint32_t t1=h+s1+choose+constants[i]+words[i];
            std::uint32_t s0=rotate(a,2)^rotate(a,13)^rotate(a,22);
            std::uint32_t majority=(a&b)^(a&c)^(b&c);
            std::uint32_t t2=s0+majority;
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;
        state_[4]+=e;state_[5]+=f;state_[6]+=g;state_[7]+=h;
    }

public:
    void update(const void *data, std::size_t length) {
        const unsigned char *cursor = static_cast<const unsigned char *>(data);
        bytes_ += length;
        while (length) {
            std::size_t amount = std::min(length, sizeof(buffer_) - buffered_);
            std::memcpy(buffer_ + buffered_, cursor, amount);
            buffered_ += amount; cursor += amount; length -= amount;
            if (buffered_ == sizeof(buffer_)) { transform(buffer_); buffered_ = 0; }
        }
    }

    std::string final() {
        std::uint64_t bits = bytes_ * 8U;
        unsigned char padding[72]{0x80};
        update(padding, buffered_ < 56 ? 56 - buffered_ : 120 - buffered_);
        unsigned char length[8];
        for (int i = 0; i < 8; ++i) length[7-i] = static_cast<unsigned char>(bits >> (i*8U));
        update(length, 8);
        std::string result(32, '\0');
        for (int i = 0; i < 8; ++i) {
            result[i*4]=static_cast<char>(state_[i]>>24U);
            result[i*4+1]=static_cast<char>(state_[i]>>16U);
            result[i*4+2]=static_cast<char>(state_[i]>>8U);
            result[i*4+3]=static_cast<char>(state_[i]);
        }
        return result;
    }
};

inline std::string sha256(const std::string &data) {
    Sha256 hash; hash.update(data.data(), data.size()); return hash.final();
}

inline bool secureRandom(void *buffer, std::size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    unsigned char *cursor = static_cast<unsigned char *>(buffer);
    while (length) {
        ssize_t count = read(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return false; }
        cursor += count; length -= static_cast<std::size_t>(count);
    }
    close(fd);
    return true;
}

inline std::string randomBytes(std::size_t length) {
    std::string result(length, '\0');
    if (!secureRandom(&result[0], length)) result.clear();
    return result;
}

inline std::string hmacSha256(const std::string &keyInput, const std::string &message) {
    std::string key = keyInput.size() > 64 ? sha256(keyInput) : keyInput;
    key.resize(64, '\0');
    std::string inner(64, '\0'), outer(64, '\0');
    for (int i = 0; i < 64; ++i) {
        inner[i] = static_cast<char>(static_cast<unsigned char>(key[i]) ^ 0x36U);
        outer[i] = static_cast<char>(static_cast<unsigned char>(key[i]) ^ 0x5cU);
    }
    return sha256(outer + sha256(inner + message));
}

inline bool constantTimeEqual(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    unsigned char difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return difference == 0;
}

class Aes256 {
    std::array<unsigned char, 240> roundKeys_{};
    static unsigned char multiply(unsigned char a, unsigned char b) {
        unsigned char result = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1U) result ^= a;
            bool high = a & 0x80U; a <<= 1U; if (high) a ^= 0x1bU; b >>= 1U;
        }
        return result;
    }
    static unsigned char inverseByte(unsigned char value) {
        if (!value) return 0;
        unsigned char result = 1, base = value;
        for (int exponent = 254; exponent; exponent >>= 1) {
            if (exponent & 1) result = multiply(result, base);
            base = multiply(base, base);
        }
        return result;
    }
    static const std::array<unsigned char, 256> &sboxTable() {
        static const std::array<unsigned char, 256> table = [] {
            std::array<unsigned char, 256> values{};
            for (int i = 0; i < 256; ++i) {
                unsigned char x = inverseByte(static_cast<unsigned char>(i));
                values[i] = static_cast<unsigned char>(
                    x ^ ((x<<1)|(x>>7)) ^ ((x<<2)|(x>>6)) ^
                    ((x<<3)|(x>>5)) ^ ((x<<4)|(x>>4)) ^ 0x63U);
            }
            return values;
        }();
        return table;
    }
    static unsigned char sbox(unsigned char value) { return sboxTable()[value]; }
    static unsigned char inverseSbox(unsigned char value) {
        static const std::array<unsigned char, 256> inverse = [] {
            std::array<unsigned char, 256> values{};
            for (int i = 0; i < 256; ++i) values[sboxTable()[i]] = static_cast<unsigned char>(i);
            return values;
        }();
        return inverse[value];
    }
    static void addKey(unsigned char state[16], const unsigned char *key) {
        for (int i = 0; i < 16; ++i) state[i] ^= key[i];
    }
    static void shiftRows(unsigned char s[16]) {
        unsigned char t[16];
        for (int r=0;r<4;++r) for(int c=0;c<4;++c) t[r+4*c]=s[r+4*((c+r)%4)];
        std::memcpy(s,t,16);
    }
    static void inverseShiftRows(unsigned char s[16]) {
        unsigned char t[16];
        for (int r=0;r<4;++r) for(int c=0;c<4;++c) t[r+4*c]=s[r+4*((c-r+4)%4)];
        std::memcpy(s,t,16);
    }
    static void mixColumns(unsigned char s[16]) {
        for(int c=0;c<4;++c){unsigned char *a=s+4*c;unsigned char t[4];
            t[0]=multiply(a[0],2)^multiply(a[1],3)^a[2]^a[3];
            t[1]=a[0]^multiply(a[1],2)^multiply(a[2],3)^a[3];
            t[2]=a[0]^a[1]^multiply(a[2],2)^multiply(a[3],3);
            t[3]=multiply(a[0],3)^a[1]^a[2]^multiply(a[3],2);std::memcpy(a,t,4);}
    }
    static void inverseMixColumns(unsigned char s[16]) {
        for(int c=0;c<4;++c){unsigned char *a=s+4*c;unsigned char t[4];
            t[0]=multiply(a[0],14)^multiply(a[1],11)^multiply(a[2],13)^multiply(a[3],9);
            t[1]=multiply(a[0],9)^multiply(a[1],14)^multiply(a[2],11)^multiply(a[3],13);
            t[2]=multiply(a[0],13)^multiply(a[1],9)^multiply(a[2],14)^multiply(a[3],11);
            t[3]=multiply(a[0],11)^multiply(a[1],13)^multiply(a[2],9)^multiply(a[3],14);std::memcpy(a,t,4);}
    }
public:
    explicit Aes256(const std::string &key) {
        std::memcpy(roundKeys_.data(), key.data(), 32);
        int generated=32; unsigned char rcon=1; unsigned char temp[4];
        while(generated<240){std::memcpy(temp,roundKeys_.data()+generated-4,4);
            if(generated%32==0){unsigned char first=temp[0];temp[0]=sbox(temp[1])^rcon;temp[1]=sbox(temp[2]);temp[2]=sbox(temp[3]);temp[3]=sbox(first);rcon=multiply(rcon,2);}
            else if(generated%32==16)for(auto &v:temp)v=sbox(v);
            for(int i=0;i<4;++i){roundKeys_[generated]=roundKeys_[generated-32]^temp[i];++generated;}}
    }
    void encryptBlock(unsigned char block[16]) const {
        addKey(block,roundKeys_.data());
        for(int round=1;round<14;++round){for(int i=0;i<16;++i)block[i]=sbox(block[i]);shiftRows(block);mixColumns(block);addKey(block,roundKeys_.data()+round*16);}
        for(int i=0;i<16;++i)block[i]=sbox(block[i]);shiftRows(block);addKey(block,roundKeys_.data()+224);
    }
    void decryptBlock(unsigned char block[16]) const {
        addKey(block,roundKeys_.data()+224);
        for(int round=13;round>0;--round){inverseShiftRows(block);for(int i=0;i<16;++i)block[i]=inverseSbox(block[i]);addKey(block,roundKeys_.data()+round*16);inverseMixColumns(block);}
        inverseShiftRows(block);for(int i=0;i<16;++i)block[i]=inverseSbox(block[i]);addKey(block,roundKeys_.data());
    }
};

inline std::string aes256CbcEncrypt(const std::string &key, const std::string &iv, const std::string &plain) {
    std::string input=plain; unsigned char padding=static_cast<unsigned char>(16-input.size()%16); input.append(padding,static_cast<char>(padding));
    std::string output(input.size(),'\0'), previous=iv; Aes256 aes(key);
    for(std::size_t offset=0;offset<input.size();offset+=16){unsigned char block[16];for(int i=0;i<16;++i)block[i]=static_cast<unsigned char>(input[offset+i])^static_cast<unsigned char>(previous[i]);aes.encryptBlock(block);std::memcpy(&output[offset],block,16);previous.assign(reinterpret_cast<char*>(block),16);}
    return output;
}

inline bool aes256CbcDecrypt(const std::string &key, const std::string &iv, const std::string &cipher, std::string &plain) {
    if(key.size()!=32||iv.size()!=16||cipher.empty()||cipher.size()%16) return false;
    plain.resize(cipher.size()); std::string previous=iv; Aes256 aes(key);
    for(std::size_t offset=0;offset<cipher.size();offset+=16){unsigned char block[16];std::memcpy(block,cipher.data()+offset,16);unsigned char original[16];std::memcpy(original,block,16);aes.decryptBlock(block);for(int i=0;i<16;++i)plain[offset+i]=static_cast<char>(block[i]^static_cast<unsigned char>(previous[i]));previous.assign(reinterpret_cast<char*>(original),16);}
    unsigned char padding=static_cast<unsigned char>(plain.back()); if(!padding||padding>16||padding>plain.size())return false;
    unsigned char difference=0;for(std::size_t i=0;i<padding;++i)difference|=static_cast<unsigned char>(plain[plain.size()-1-i])^padding;
    if(difference)return false;plain.resize(plain.size()-padding);return true;
}
