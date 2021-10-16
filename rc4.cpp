
#include <iostream>
#include <numeric>
#include <cstring>

using namespace std;

unsigned char* KSA(const char* key, int keyLength) {
    unsigned char* state = static_cast<unsigned char*>(malloc(256));
    std::iota(state, state + 256, 0);
    
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + state[i] + key[i % keyLength]) % 256;
        std::swap(state[i], state[j]);
    }
    
    return state;
}

unsigned char* PRGA(unsigned char* state, int skipBytes, int nKeys) {
    int i = 0;
    int j = 0;
    int counter = 0;
    while (counter < skipBytes) {
        i = (i + 1) % 256;
        j = (j + state[i]) % 256;
        std::swap(state[i], state[j]);
        ++counter;
    }
    
    unsigned char* keys = static_cast<unsigned char*>(malloc(nKeys));
    counter = 0;
    while (counter < nKeys) {
        i = (i + 1) % 256;
        j = (j + state[i]) % 256;
        std::swap(state[i], state[j]);
        keys[counter] = (state[i] + state[j]) % 256;
        ++counter;
    }
    
    return keys;
}

unsigned char* RC4(const char* key, const char* plainText, int skipBytes) {
    const int keyLength = std::strlen(key);
    unsigned char* state = KSA(key, keyLength);
    const int nKeys = std::strlen(plainText);
    unsigned char* keys = PRGA(state, skipBytes, nKeys);
    
    unsigned char* cipherText = static_cast<unsigned char*>(malloc(nKeys));
    for (int i = 0; i < nKeys; ++i) {
        cipherText[i] = (static_cast<unsigned char>(plainText[i]) ^ state[keys[i]]);
    }
    free(state);
    free(keys);
    
    return cipherText;
}

int main()
{
    const char* key = "HENDO";
    const char* plainText = "Ba jan, Ba jan!";
    unsigned char* cipherText = RC4(key, plainText, 1000);
    std::cout << cipherText << std::endl;
    for (int i = 0; i < strlen(plainText); ++i) {
        std::cout << std::hex << static_cast<int>(cipherText[i]) << " ";
    }
    free(cipherText);

    return 0;
}