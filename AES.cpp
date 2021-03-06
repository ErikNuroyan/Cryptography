#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

class AES {
    public:
    
    AES() = delete;
    
    AES(const unsigned char* key) {
        if (std::strlen(reinterpret_cast<const char*>(key)) != 16) {
            std::cout << "Invalid key length" << std::endl;
        }
        state = static_cast<unsigned char*>(malloc(16));
        roundKeys = generateRoundKeys(key);
    }
    
    ~AES() {
        free(state);
        for (unsigned char* k : roundKeys) {
            free(k);
        }
    }
    
    void encrypt(const unsigned char* plainText, unsigned char* cipherText) {
        std::memcpy(state, plainText, 16);
        
        //Round 0
        addRoundKey(roundKeys[0]);
        
        //Rounds 1 up to 9 
        for (int i = 1; i <= 9; ++i) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(roundKeys[i]);
        }
        
        //Final round
        subBytes();
        shiftRows();
        addRoundKey(roundKeys[10]);
        
        std::memcpy(cipherText, state, 16);
    }
    
    void decrypt(const unsigned char* cipherText, unsigned char* plainText) {
        std::memcpy(state, cipherText, 16);
        
        //Round 0
        const int nRounds = roundKeys.size();
        addRoundKey(roundKeys[nRounds - 1]);
        
        //Rounds 1 up to 9 
        for (int i = 9; i >= 1; --i) {
            invSubBytes();
            invShiftRows();
            invMixColumns();
            unsigned char* tmp = static_cast<unsigned char*>(malloc(16));
            std::memcpy(tmp, roundKeys[i], 16);
            invMixColumns(tmp);
            addRoundKey(tmp);
            free(tmp);
        }
        
        //Final round
        invSubBytes();
        invShiftRows();
        addRoundKey(roundKeys[0]);
        
        std::memcpy(plainText, state, 16);
    }
    
    private:
    unsigned char* state;
    std::vector<unsigned char*> roundKeys;
    
    const unsigned char sBox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    
    const unsigned char invSbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    
    const unsigned char rCon[40] = {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
        0x1b, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00
    };
    
    void subBytes() {
        for (int i = 0; i < 16; ++i) {
            state[i] = sBox[(state[i] / 16) * 16 + (state[i] % 16)];
        }
    }
    
    void shiftRows() {
        std::stringstream result;
        for (int j = 0; j < 4; ++j) {
            for (int i = 0; i < 4; ++i) {
                result << state[i + 4 * ((i + j) % 4)];
            }
        }
        std::memcpy(state, result.str().c_str(), 16);
    }
    
    unsigned char mulBy2(unsigned char x) {
        unsigned char result;
        unsigned char rightShift = (x >> 7) & 1;
        result = (x << 1);
        
        return result ^ (rightShift * 0x1b);
    }
    
    void mixColumns() {
        for (int i = 0; i < 4; ++i) {
            unsigned char tmp[4];
            unsigned char multipliedBy2[4]; //Keeps element in column multipled by 2
            std::memcpy(tmp, state + i * 4, 4); //The ith column is copied to tmp
            
            //Multiplies each column with {02} 
            for (int j = 0; j < 4; ++j) {
                multipliedBy2[j] = mulBy2(state[i * 4 + j]); 
            }
            
            //Multiplication by {03} is the same as first multiplied by {02} and XORed with {01} 
            state[i * 4] = multipliedBy2[0] ^ tmp[3] ^ tmp[2] ^ multipliedBy2[1] ^ tmp[1];     
            state[i * 4 + 1] = multipliedBy2[1] ^ tmp[0] ^ tmp[3] ^ multipliedBy2[2] ^ tmp[2]; 
            state[i * 4 + 2] = multipliedBy2[2] ^ tmp[1] ^ tmp[0] ^ multipliedBy2[3] ^ tmp[3]; 
            state[i * 4 + 3] = multipliedBy2[3] ^ tmp[2] ^ tmp[1] ^ multipliedBy2[0] ^ tmp[0]; 
        }
    }
    
    std::string rotWord(unsigned char* word) {
        std::stringstream ss;
        for (int i = 0; i < 4; ++i) {
            ss << word[(i + 1) % 4];
        }
        
        return ss.str();
    }
    
    void invSubBytes() {
        for (int i = 0; i < 16; ++i) {
            state[i] = invSbox[(state[i] / 16) * 16 + (state[i] % 16)];
        }
    }
    
    void invShiftRows() {
        std::stringstream result;
        for (int j = 0; j < 4; ++j) {
            for (int i = 0; i < 4; ++i) {
                const int col = (i - j <= 0 ? i - j + 4 : i - j);
                result << state[i + 4 * (4 - col)];
            }
        }
        std::memcpy(state, result.str().c_str(), 16);
    }
    
    unsigned char mulBy9(unsigned char x)
    {
        return mulBy2(mulBy2(mulBy2(x))) ^ x;
    }
    
    unsigned char mulBy11(unsigned char x)
    {
        return mulBy2(mulBy2(mulBy2(x)) ^ x) ^ x;
    }
    
    unsigned char mulBy13(unsigned char x)
    {
        return mulBy2(mulBy2(mulBy2(x) ^ x)) ^ x;
    }
    
    unsigned char mulBy14(unsigned char x)
    {
        return mulBy2(mulBy2(mulBy2(x) ^ x) ^ x);
    }
    
    void invMixColumns(unsigned char* key = nullptr) {
        unsigned char* target = !key ? state : key;
        for (int i = 0; i < 4; ++i) {
            unsigned char tmp[4];
            std::memcpy(tmp, target + i * 4, 4); //The ith column is copied to tmp
            
            target[i * 4] = mulBy14(tmp[0]) ^ mulBy11(tmp[1]) ^ mulBy13(tmp[2]) ^ mulBy9(tmp[3]);     
            target[i * 4 + 1] = mulBy9(tmp[0]) ^ mulBy14(tmp[1]) ^ mulBy11(tmp[2]) ^ mulBy13(tmp[3]); 
            target[i * 4 + 2] = mulBy13(tmp[0]) ^ mulBy9(tmp[1]) ^ mulBy14(tmp[2]) ^ mulBy11(tmp[3]); 
            target[i * 4 + 3] = mulBy11(tmp[0]) ^ mulBy13(tmp[1]) ^ mulBy9(tmp[2]) ^ mulBy14(tmp[3]); 
        }
    }
    
    std::vector<unsigned char*> generateRoundKeys(const unsigned char* key) {
        std::vector<unsigned char*> result;
        //For the Round 0
        unsigned char* roundKey = static_cast<unsigned char*>(malloc(16));
        std::memcpy(roundKey, key, 16);
        result.push_back(roundKey);
        
        //For remaining 10 Rounds
        for (int i = 0; i < 10; ++i) {
            roundKey = static_cast<unsigned char*>(malloc(16));
            const unsigned char* rWord = reinterpret_cast<const unsigned char*>(rotWord(result[i] + 12).c_str());
            for (int k = 0; k < 4; ++k) {
                roundKey[k] = result[i][k] ^ sBox[(rWord[k] / 16) * 16 + (rWord[k] % 16)] ^ rCon[i * 4 + k];
            }
            for (int j = 1; j < 4; ++j) {
                for (int h = 0; h < 4; ++h) {
                    roundKey[4 * j + h] = result[i][4 * j + h] ^ roundKey[4 * (j - 1) + h];
                }
            }
            result.push_back(roundKey);
        }
        return result;
    }
    
    void addRoundKey(const unsigned char* roundKey) {
        for (int i = 0; i < 16; ++i) {
            state[i] ^= roundKey[i];
        }
    }
};

//t should be 16 bytes long
void printHex(const unsigned char* t) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            std::cout << std::hex << int(t[i + j * 4]) << " ";
        }
        std::cout << std::endl;
    }
}

int main()
{
    AES a(reinterpret_cast<const unsigned char*>("Hi,I am your key"));
    unsigned char* cipherText = static_cast<unsigned char*>(std::malloc(16));
    const unsigned char* plainText = reinterpret_cast<const unsigned char*>("Yeah you know me");
    
    std::cout << "Plaintext:" << std::endl;
    printHex(plainText);
    std::cout << std::endl;
    
    a.encrypt(plainText, cipherText);
    std::cout << "Cyphertext:" << std::endl;
    printHex(cipherText);
    std::cout << std::endl;
    
    unsigned char* p = static_cast<unsigned char*>(std::malloc(16));
    a.decrypt(cipherText, p);
    std::cout << "Plaintext:" << std::endl;
    printHex(p);

    free(cipherText);
    free(p);
    
    return 0;
}
