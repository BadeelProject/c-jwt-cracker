#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <cmath>
#include <cassert>
#include <cstring>
#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>

#include <base64/base64.h>

using std::cout;
using std::endl;

//-----------------------------------------------------------------------------
// Globals
//-----------------------------------------------------------------------------

int gNumThreads = 4;
size_t gMaxSecretLen = 6;

// The secret is potentially one item in the power set of the entire alphabet
std::string gAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz"
                        "0123456789";

// Assuming no hash collision, since all of our threads are using a different
// secret, no two threads should ever find a valid secret at the same time
// and thus we do not need mutual exclusion to protect this variable.
// There might be a race condition where a thread reads this immediately before
// another thread finds the secret; in which case, we just waste 1 more cycle
bool gFoundSecret = false;
std::string gSecret;

struct ThreadData {
    // Parameters
    EVP_MD* hashAlg;
    int startChar;
    int endChar;

    const unsigned char* toEncrypt; // Passed into HMAC to compute signature; base64(header) + '.' + base64(payload)
    unsigned int toEncryptLen;

    const unsigned char* origSig; // Original signature to compare against
    unsigned int origSigLen;

    // Space for current secret being checked
    int posIdx;
    int charOffset;
    unsigned char* secretBuffer;
    unsigned int secretBufferLen;

    // Space for HMAC output (better to have a const space than constantly reallocating)
    unsigned char* sigBuffer;
    unsigned int sigBufferLen;

    ThreadData(int startChar, int endChar, const char* toEncrypt, const char* origSig)
    : hashAlg((EVP_MD *) EVP_sha256())
    , startChar(startChar)
    , endChar(endChar)
    , toEncrypt((const unsigned char*)toEncrypt)
    , toEncryptLen(strlen(toEncrypt))
    , origSig((const unsigned char*)origSig)
    , origSigLen(strlen(origSig)) {
        posIdx = 0;
        charOffset = -1;
        secretBuffer = (unsigned char*)calloc(gMaxSecretLen, sizeof(char));
        secretBufferLen = 0;

        sigBuffer = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
        sigBufferLen = 0;
    }

    ~ThreadData() {
        delete sigBuffer;
        delete secretBuffer;
    }
};

typedef struct ThreadData ThreadData;

//-----------------------------------------------------------------------------
// Thread
//-----------------------------------------------------------------------------

bool isValidSecret(ThreadData* threadData) {
    if (gFoundSecret) {
        pthread_exit(NULL);
    }

    HMAC(
        threadData->hashAlg,
        threadData->secretBuffer, threadData->secretBufferLen,
        threadData->toEncrypt, threadData->toEncryptLen,
        threadData->sigBuffer, &threadData->sigBufferLen
    );

    assert(threadData->origSigLen == threadData->sigBufferLen);
    return memcmp(threadData->sigBuffer, threadData->origSig, threadData->origSigLen) == 0;
}

// bool brute_impl(struct s_thread_data *data, char* str, int index, int max_depth)
// {
//     for (int i = 0; i < g_alphabet_len; ++i)
//     {
//         // The character at "index" in "str" successvely takes the value
//         // of each symbol in the alphabet
//         str[index] = g_alphabet[i];

//         // If just changed the last letter, that means we generated a
//         // permutation, so we check it
//         if (index == max_depth - 1) {
//             // If we found the key, we return, otherwise we continue.
//             // By continuing, the current letter (at index "index")
//             // will be changed to the next symbol in the alphabet
//             if (check(data, (const char *) str, max_depth)) return true;
//         }
//         // If the letter we just changed was not the last letter of
//         // the permutation we are generating, recurse to change the
//         // letter at the next index.
//         else {
//             // If this condition is met, that means we found the key.
//             // Otherwise the loop will continue and change the current
//             // character to the next letter in the alphabet.
//          if (brute_impl(data, str, index + 1, max_depth)) return true;
//         }
//     }

//     // If we are here, we tried all the permutations without finding a match
//  return false;
// } 

bool getNextSecret(ThreadData* threadData) {
    int posIdx = threadData->posIdx;
    int charOffset = threadData->charOffset;

    int firstChar = (idx < 1) ? thread->startChar   : 0;
    int lastChar = (idx < 1) ? threadData->endChar : gAlphabet.size() - 1;
    
    // Advance counters
    charOffset++;
    if (charOffset > lastChar) {
        // Wrap around if we finished the alphabet for current character position
        // e.g. Z000 prev
        //      AA00 next
        //       ^-- posIdx
        //           charIdx will reset back to start
        charOffset = firstChar;
        posIdx++;

        if (posIdx > gMaxSecretLen) {
            // Exhausted search space
            return false;
        }
    }

    threadData->posIdx = posIdx;
    threadData->charOffset = charOffset;
    threadData->secretBuffer[posIdx] = gAlphabet[charOffset];
    threadData->secretBufferLen = posIdx + 1;

    return true;
}

void bruteForceThread(ThreadData* threadData) {
    while (getNextSecret(threadData)) {
        if (isValidSecret(threadData)) {
            gFoundSecret = true;
            gSecret = (char*)threadData->secretBuffer;
            return;
        }
    }
}

void bruteForceJWT(const std::string &toEncrypt, const std::string &origSig) {
    ThreadData* threadData[gNumThreads];
    pthread_t tid[gNumThreads];

    int charPerThread = std::ceil((double) gAlphabet.size() / gNumThreads);
    for (int i = 0; i < gNumThreads; ++i) {
        int startChar = (i * charPerThread);
        int endChar = std::min(startChar + charPerThread - 1, (int)gAlphabet.size());

        cout << "Starting thread to search from " << startChar << " to " << endChar << endl;

        threadData[i] = new ThreadData(startChar, endChar, toEncrypt.c_str(), origSig.c_str());
        pthread_create(&tid[i], NULL, (void *(*)(void *)) bruteForceThread, threadData[i]);
    }

    for (int i = 0; i < gNumThreads; ++i) {
        pthread_join(tid[i], NULL);
    }
}


//-----------------------------------------------------------------------------
// Main
//-----------------------------------------------------------------------------

void usage(const char *cmd) {
    cout << cmd << " <token> [numThreads] [maxLen] [alphabet]" << endl;
    cout << endl;

    cout << "Defaults:" << endl;
    cout << "numThreads = " << gNumThreads << endl;
    cout << "maxLen = " << gMaxSecretLen << endl;
    cout << "alphabet = " << gAlphabet << endl;
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    std::stringstream jwt;
    jwt << argv[1];

    if (argc > 2) {
        gNumThreads = atoi(argv[2]);
    }
    if (argc > 3) {
        gMaxSecretLen = (size_t) atoi(argv[3]);
    }
    if (argc > 4) {
        gAlphabet = argv[4];
    }

    std::string header;
    getline(jwt, header, '.');

    std::string payload;
    getline(jwt, payload, '.');

    std::string origSig;
    getline(jwt, origSig, '.');    

    // Our goal is to find the secret to HMAC this string into our origSig
    std::string toEncrypt = header + '.' + payload;
    bruteForceJWT(toEncrypt, origSig);

    if (gFoundSecret) {
        cout << "No secret found" << endl;
    } else {
        cout << "Secret: " << gSecret << endl;
    }

    return 0;
}
