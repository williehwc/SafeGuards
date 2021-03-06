// CRYPTOGRAPHY FUNCTIONS
// snake_case functions by Willie, with help from
// https://www.dynamsoft.com/codepool/how-to-use-openssl-generate-rsa-keys-cc.html
// https://stackoverflow.com/questions/5927164/how-to-generate-rsa-private-key-using-openssl
// camelCase functions taken almost verbatim from
// https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59

// #ifdef PYBIND
// #include <pybind11/pybind11.h>
// #endif

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string.h>
#include <string>
#include <iostream>

#define RSA_BITS 2048

bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return false;
  }
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

RSA* createPublicRSA(std::string key) {
  RSA *rsa = NULL;
  BIO *keybio;
  const char* c_string = key.c_str();
  keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  return rsa;
}

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
  RSA* publicRSA = createPublicRSA(publicKey);
  if (publicRSA == NULL) {
    fprintf(stderr, "Public key error, signature verification will fail\n");
    return false;
  }
  unsigned char* encMessage;
  size_t encMessageLength;
  bool authentic;
  Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
  return result & authentic;
}

bool RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
      return false;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
      return false;
  }
  EVP_MD_CTX_free(m_RSASignCtx);
  return true;
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
  (*base64Text)[(*bufferPtr).length] = '\0';
}

char* signMessage(RSA *rsa_key, std::string plainText) {
  unsigned char* encMessage;
  char* base64Text;
  size_t encMessageLength;
  RSASign(rsa_key, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
  // std::cout << encMessageLength << std::endl;
  Base64Encode(encMessage, encMessageLength, &base64Text);
  // std::cout << strlen(base64Text) << std::endl;
  free(encMessage);
  return base64Text;
}

#ifdef FOR_C
extern "C" {
#endif

RSA *create_rsa_key() {
    RSA *rsa_key = RSA_new();
    BIGNUM *rsa_exponent = BN_new();
    BN_set_word(rsa_exponent, RSA_F4); // RSA_F4 = 65537
    int rsa_return = RSA_generate_key_ex(rsa_key, RSA_BITS, rsa_exponent, NULL);
    if (!rsa_return) {
        perror("Cannot generate RSA key pair");
    }
    return rsa_key;
}

// Convert public key to PEM format so it can be passed as a string
char *rsa_to_pem_public_key(RSA *rsa_key) {
    BIO *key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(key_bio, rsa_key);
    int key_len = BIO_pending(key_bio);
    char *pem_public_key = (char*)calloc(key_len + 1, 1); // null-terminate
    BIO_read(key_bio, pem_public_key, key_len);
    BIO_free_all(key_bio);
    return pem_public_key;
}

bool verifySignatureC(char *publicKey, char *plainText, char *signatureBase64) {
    std::string publicKeyStr(publicKey);
    std::string plainTextStr(plainText);
    return verifySignature(publicKeyStr, plainTextStr, signatureBase64);
}

char *signMessageC(RSA *rsa_key, char *plainText) {
    std::string plainTextStr(plainText);
    return signMessage(rsa_key, plainTextStr);
}

#ifdef FOR_C
}
#endif
