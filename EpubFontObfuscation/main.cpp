#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <algorithm>
#include <utility>
#include <string>

class SHA1digest
{
private:
    template<int n, int w = 32>
    static uint32_t rotr(uint32_t x)
    {
        return (x >> n) | (x << (w - n));
    }
    template<int n, int w = 32>
    static uint32_t rotl(uint32_t x)
    {
        return (x << n) | (x >> (w - n));
    }
    static uint32_t sha1_ft(unsigned t, uint32_t x, uint32_t y, uint32_t z)
    {
        if(t < 20)
            return (x & y) ^ (~x & z);
        if(t < 40)
            return x ^ y ^ z;
        if(t < 60)
            return (x & y) ^ (x & z) ^ (y & z);
        // if(t < 80)
        return x ^ y ^ z;
    }
public:
    SHA1digest(void)
        : h0(0x67452301)
        , h1(0xefcdab89)
        , h2(0x98badcfe)
        , h3(0x10325476)
        , h4(0xc3d2e1f0)
    {
    }
    uint32_t h0;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    unsigned char get(int n) const
    {
        n %= 20;
        if(n < 4)
            return h0 >> (24 - 8 * n);
        if(n < 8)
            return h1 >> (24 - 8 * (n - 4));
        if(n < 12)
            return h2 >> (24 - 8 * (n - 8));
        if(n < 16)
            return h3 >> (24 - 8 * (n - 12));
        //if(n < 20)
        return h4 >> (24 - 8 * (n - 16));
    }
    void calcSHA1(const char *M, size_t length)
    {
        uint32_t W[16];
        uint32_t K[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        unsigned char *temp = (unsigned char *)W;
        memset(W, 0, sizeof(W));
        if(length < 56)
            memcpy(W, M, length);
        temp[length] = 0x80;
        for(unsigned i = 0; i < 16; ++i)
        {
            std::swap(temp[i * 4], temp[i * 4 + 3]);
            std::swap(temp[i * 4 + 1], temp[i * 4 + 2]);
        }
        W[15] = length * 8;
        for(unsigned t = 0; t < 80; ++t)
        {
            if(t >= 16)
                W[t & 0xf] = rotl<1>(W[(t + 13) & 0xf] ^ W[(t + 8) & 0xf] ^ W[(t + 2) & 0xf] ^ W[t & 0xf]);
            uint32_t T = rotl<5>(a) + sha1_ft(t, b, c, d) + e + K[t / 20] + W[t & 0xf];
            e = d;
            d = c;
            c = rotl<30>(b);
            b = a;
            a = T;
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }
        SHA1digest ret;
        h0 = ret.h0 + a;
        h1 = ret.h1 + b;
        h2 = ret.h2 + c;
        h3 = ret.h3 + d;
        h4 = ret.h4 + e;
    }
};

std::pair<unsigned char*, unsigned> get_file(const std::string& filename)
{
    struct stat stbuf;
    int fd = open(filename.c_str(), O_RDONLY);
    if(fd == -1)
    {
        return std::pair<unsigned char*, unsigned>(NULL, 0);
    }
    FILE *fp = fdopen(fd, "rb");
    if(fp == NULL)
    {
        close(fd);
        return std::pair<unsigned char*, unsigned>(NULL, 0);
    }
    if(fstat(fd, &stbuf) == -1)
    {
        fclose(fp);
        return std::pair<unsigned char*, unsigned>(NULL, 0);
    }
    unsigned file_size = stbuf.st_size;
    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if(buffer == NULL)
    {
        fclose(fp);
        return std::pair<unsigned char*, unsigned>(NULL, 0);
    }
    fread(buffer, file_size, 1, fp);
    fclose(fp);
    return std::pair<unsigned char*, unsigned>(buffer, file_size);
}

int main(int argc, char *argv[])
{
    std::pair<unsigned char*, unsigned> src;
    std::string uid;
    std::string dst;
    if(argc < 3)
    {
        printf("EpubFontObfuscation input_font_file unique_identifier [output_font_file]\n");
        printf("EpubFontObfuscation: this command\n");
        printf("input_font_file:     file path of the target font\n");
        printf("unique_identifier:   unique-identifier of the target EPUB\n");
        printf("output_font_file:    path for the output font (optional)\n");
        return -1;
    }
    src = get_file(argv[1]);
    if(src.first == NULL)
    {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        return -1;
    }
    uid = argv[2];
    dst = (argc >= 3 && argv[3]) ? argv[3] : "";
    SHA1digest H;
    H.calcSHA1(uid.c_str(), uid.length());
    auto n = std::min(1040U, src.second);
    for(int i = 0; i < n; ++i)
        src.first[i] = src.first[i] ^ H.get(i);
    if(auto fp = dst.empty() ? stdout : fopen(dst.c_str(), "wb"))
    {
        fwrite(src.first, src.second, 1, fp);
        fclose(fp);
    }
    else
    {
        fprintf(stderr, "Failed to open %s\n", argv[3]);
        return -1;
    }
    return 0;
}
