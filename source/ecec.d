module ecec;

import std.stdint : uint64_t;
import core.stdc.stdarg : va_list;
import std.string : toStringz;
import core.stdc.stdlib: free;
import core.stdc.stdint : uint32_t, uint8_t;

/*

ecec headers for d
https://github.com/web-push-libs/ecec

*/

enum ECE_OK = 0;
enum ECE_WEBPUSH_DEFAULT_RS = 4096;
enum ECE_WEBPUSH_AUTH_SECRET_LENGTH = 16;
enum ECE_WEBPUSH_PUBLIC_KEY_LENGTH = 65;
enum ECE_WEBPUSH_PRIVATE_KEY_LENGTH = 32;

extern (C) nothrow {

   int ece_webpush_generate_keys(uint8_t* rawRecvPrivKey, size_t rawRecvPrivKeyLen,
                          uint8_t* rawRecvPubKey, size_t rawRecvPubKeyLen,
                          uint8_t* authSecret, size_t authSecretLen);

   size_t ece_aes128gcm_payload_max_length(uint32_t rs, size_t padLen,
                                    size_t plaintextLen);

   int ece_webpush_aes128gcm_encrypt(const uint8_t* rawRecvPubKey,
                              size_t rawRecvPubKeyLen,
                              const uint8_t* authSecret, size_t authSecretLen,
                              uint32_t rs, size_t padLen,
                              const uint8_t* plaintext, size_t plaintextLen,
                              uint8_t* payload, size_t* payloadLen);

   size_t ece_aes128gcm_plaintext_max_length(const uint8_t* payload, size_t payloadLen);

   int ece_webpush_aes128gcm_decrypt(const uint8_t* rawRecvPrivKey,
                              size_t rawRecvPrivKeyLen,
                              const uint8_t* authSecret, size_t authSecretLen,
                              const uint8_t* payload, size_t payloadLen,
                              uint8_t* plaintext, size_t* plaintextLen);
}