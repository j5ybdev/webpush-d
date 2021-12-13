module webpushd;
/*

RFC8292 Spec web push (https://datatracker.ietf.org/doc/rfc8292/)
Uses ecec and openssl to send web push messages.

*/
import std.base64;
import std.json;
import std.format;
import std.file : readText;
import std.conv : to;
import std.array : appender, split;
import std.string : representation;
import std.algorithm : count, startsWith, endsWith;
import std.uni : toUpper;
import std.string : strip;
import std.exception : enforce;
import std.datetime : Duration, Clock, dur, UTC;
import ecec; // https://github.com/web-push-libs/ececd
import deimos.openssl.sha : SHA256_DIGEST_LENGTH;
import deimos.openssl.pem;
import deimos.openssl.bn : BN_bn2bin;

private enum WEB_PUSH_ENCODING =  "aes128gcm";
private enum WEB_PUSH_CONTENT_TYPE = "application/octet-stream";
private enum PUB_KEY_BYTE_L = 65;
private enum PEM_COMMENT = "-----";
private enum ES_CURVE_ID = NID_X9_62_prime256v1;
private enum JWT_ALG = "ES256";
private enum MAX_PAYLOAD_L = 4096;

struct WebPushOptions {
   /// sub for mailto link for the administrative contact for this feed
   string contact;
   /// optional topic to group messages by
   string topic;
   /// seconds the notification should stay in storage if the remote user agent isn’t actively connected
   int ttl = 0;
   /// control whether the message is processed during low battery conditions, etc
   Urgency urgency = Urgency.NORMAL;
}

enum Urgency: string {
   VERY_LOW = "very-low",
   LOW = "low",
   NORMAL = "normal",
   HIGH = "high"
}

struct PushSubscription {
   string endpoint;
   PushSubKeys keys;
}

struct PushSubKeys {
   string p256dh;
   string auth;
}

/// Holder of ECDSA P-256 Keys used for the Web Push authorization
/// Must be a class so that keys aren't free'd if struct is copied
class WebPushKeys {
   /// raw ECDSA P-256 public key in base64
   string rawPublicKey;
   /// openssl format private key
   EC_KEY* ecPrivateKey = null;
   /// openssl format public key
   EC_KEY* ecPublicKey  = null;
   
   /// Take in PEM format keys and initialize struct with native formats
   this(string pemPrvKey, string pemPubKey) {
      // Transform public key into raw form for the authorization header
      rawPublicKey = pemPubKeyToX962Base64(pemPubKey);

      ecPrivateKey = loadESPrivateKey(ES_CURVE_ID, pemPrvKey);
      ecPublicKey  = loadESPublicKey(ES_CURVE_ID, pemPubKey);
   }

   ~this() {
      EC_KEY_free(ecPrivateKey);
      EC_KEY_free(ecPublicKey);
   }
}

struct EceKeySet {
   ubyte[ECE_WEBPUSH_PUBLIC_KEY_LENGTH] pubKey;
   ubyte[ECE_WEBPUSH_PRIVATE_KEY_LENGTH] prvKey;
   ubyte[ECE_WEBPUSH_AUTH_SECRET_LENGTH] authSecret;
}

class CryptoException : Exception {
   this(string msg, string file = __FILE__, size_t line = __LINE__) {
      super(msg, file, line);
   }
}

class VerifyException : Exception {
   this(string msg, string file = __FILE__, size_t line = __LINE__) {
      super(msg, file, line);
   }
}

class NotifyException : Exception {
   this(string msg, string file = __FILE__, size_t line = __LINE__) {
      super(msg, file, line);
   }
}

struct WebPushResp {
   short statusCode;
   string contentType;
   string respBody;

   bool success() {
      return statusCode >= 200 && statusCode < 300;
   }

   bool subExpired() {
      return statusCode == 410
         || statusCode == 404;
   }
}

interface WebPusher {
   WebPushResp send(in ref PushSubscription sub, string msg, in ref WebPushOptions options);
}

class CurlWebPusher : WebPusher {
   private WebPushKeys keys;

   this(WebPushKeys k) {
      keys = k;
   }

   WebPushResp send(in ref PushSubscription sub, string msg, in ref WebPushOptions options) {
      import std.net.curl : HTTP;
      enforce(msg.length > 0, "Message cannot be blank");

      const ubyte[] rawP256dh = Base64URLNoPadding.decode(sub.keys.p256dh);
      const ubyte[] rawAuth   = Base64URLNoPadding.decode(sub.keys.auth);

      // encrypt message body
      const ubyte[] payload = eceEncrypt(msg, rawP256dh, rawAuth);

      // generate auth header that will prove we're authorized to send to this sub
      const string authHdr = createAuthHeader(sub, options.contact, keys);

      // Send the web respuest to the subscription endpoint
      WebPushResp resp;
      auto http = HTTP(sub.endpoint);
      http.method(HTTP.Method.post);
      http.addRequestHeader("Authorization",authHdr);
      http.addRequestHeader("Content-Encoding",WEB_PUSH_ENCODING);
      http.addRequestHeader("TTL",to!string(options.ttl));
      http.addRequestHeader("Urgency",options.urgency);
      if (options.topic != null) {
         http.addRequestHeader("Topic",options.topic);
      }
      http.setPostData(payload, WEB_PUSH_CONTENT_TYPE);
      http.onReceiveHeader = (in char[] key, in char[] value) {
         if (key == "Content-Type") {
            resp.contentType = value.dup;
         }
      };
      http.onReceive = (ubyte[] data) {
         resp.respBody = cast(string) data;
         return data.length;
      };
      http.onReceiveStatusLine = (HTTP.StatusLine status) {
         resp.statusCode = status.code;
      };
      http.perform();
      return resp;
   }
}

class VibeWebPusher : WebPusher {
   private WebPushKeys keys;

   this(WebPushKeys k) {
      keys = k;
   }

   WebPushResp send(in ref PushSubscription sub, string msg, in ref WebPushOptions options) {
      import vibe.vibe : HTTPMethod, readAllUTF8;
      import vibe.http.client : requestHTTP;
      enforce(msg.length > 0, "Message cannot be blank");

      const ubyte[] rawP256dh = Base64URLNoPadding.decode(sub.keys.p256dh);
      const ubyte[] rawAuth   = Base64URLNoPadding.decode(sub.keys.auth);

      // encrypt message body
      const ubyte[] payload = eceEncrypt(msg, rawP256dh, rawAuth);

      // generate auth header that will prove we're authorized to send to this sub
      const string authHdr = createAuthHeader(sub, options.contact, keys);

      // Send the web respuest to the subscription endpoint
      WebPushResp resp;
      requestHTTP(sub.endpoint,
         (scope req) {
            req.method = HTTPMethod.POST;
            req.headers["Authorization"] = authHdr;
            req.headers["Content-Encoding"] = WEB_PUSH_ENCODING;
            req.headers["Content-Type"] = WEB_PUSH_CONTENT_TYPE;
            req.headers["TTL"] = to!string(options.ttl);
            req.headers["Urgency"] = options.urgency;
            if (options.topic != null) {
               req.headers["Topic"] = options.topic;
            }
            req.bodyWriter.write(payload);
         },
         (scope res) {           
            resp.statusCode = to!short(res.statusCode);
            resp.contentType = res.headers["Content-Type"];
            resp.respBody = res.bodyReader.readAllUTF8();
            res.destroy();
         }
      );
      return resp;
   }
}

class NoOpWebPusher : WebPusher {

   WebPushResp send(in ref PushSubscription sub, string msg, in ref WebPushOptions options) {
      WebPushResp resp = {
         statusCode: 200,
         contentType: "text/plain",
         respBody: ""
      };
      return resp;
   }
}

/// Perform encrypted content encoding on the plaintext
/// (code is translated from ece example https://github.com/web-push-libs/ecec)
ubyte[] eceEncrypt(const string plaintext, const ubyte[] rawRecvPubKey, const ubyte[] authSecret) {
   // How many bytes of padding to include in the encrypted message. Padding
   // obfuscates the plaintext length, making it harder to guess the contents
   // based on the encrypted payload length.
   size_t padLen = 0;

   // Allocate a buffer large enough to hold the encrypted payload. The payload
   // length depends on the record size, padding, and plaintext length, plus a
   // fixed-length header block. Smaller records and additional padding take
   // more space. The maximum payload length rounds up to the nearest whole
   // record, so the actual length after encryption might be smaller.
   size_t payloadLen = ece_aes128gcm_payload_max_length(ECE_WEBPUSH_DEFAULT_RS,
                                                         padLen, plaintext.length);
   if (payloadLen <= 0) {
      throw new CryptoException("Failed to calculate cipher data length from plaintext");
   }
   enforce!CryptoException(payloadLen <= MAX_PAYLOAD_L, "Payload too large");

   ubyte[] payload = new ubyte[payloadLen];

   // Encrypt the plaintext. `payload` holds the header block and ciphertext;
   // `payloadLen` is an in-out parameter set to the actual payload length.
   const int err = ece_webpush_aes128gcm_encrypt(
      rawRecvPubKey.ptr, rawRecvPubKey.length, authSecret.ptr, authSecret.length,
      ECE_WEBPUSH_DEFAULT_RS, padLen, cast(ubyte *) plaintext.representation, plaintext.length, payload.ptr,
      &payloadLen);
   
   if (err != ECE_OK) {
      throw new CryptoException(format("Failed to encrypt data. Err code %d", err));
   }

   // payloadLen might be a new smaller size
   payload = payload[0..payloadLen];

   return payload;
}

/// Decrypt the encrypted content encoding data
ubyte[] eceDecrypt(const ubyte[] encryptedData, const ubyte[] rawRecvPrivKey, const ubyte[] authSecret) {

   size_t plaintextLen = ece_aes128gcm_plaintext_max_length(encryptedData.ptr, encryptedData.length);
   if (plaintextLen <= 0) {
      throw new CryptoException("Failed to calculate plaintext length from encrypted data");
   }

   ubyte[] plaindata = new ubyte[plaintextLen - 1];

   const int err = ece_webpush_aes128gcm_decrypt(rawRecvPrivKey.ptr, rawRecvPrivKey.length,
                                 authSecret.ptr, authSecret.length,
                                 encryptedData.ptr, encryptedData.length, plaindata.ptr, &plaintextLen);

   if (err != ECE_OK) {
      throw new CryptoException(format("Failed to decrypt data. Err code %d", err));
   }

   return plaindata;
}

unittest { // Test ecec library encryption & decryption
   // test encrypting then decrypting data using libecec
   const ubyte[] rawRecvPrivKey = Base64URLNoPadding.decode("uBXQYp-6TJoAtAf-6vggalXLfxOrvF7cGQNVurRUrSI");
   const ubyte[] rawRecvPubKey = Base64URLNoPadding.decode("BB_C5J7SyjjdV5kdSJSY0GQWsks3_8mnsC48uGmzB4nqgntMUxozdD3BT01c-Vt1A1NW8xFkJJ_UxA9aa0bXZ3o");
   const ubyte[] authSecret = Base64URLNoPadding.decode("y6CjjzFmZn5DVpYQ4-iYkQ");

   // long messages should fail
   import std.exception : assertThrown;
   string longMsg;
   for (int i = 0; i < 373; i++) longMsg ~= "Test from D";
   assertThrown!CryptoException(eceEncrypt(longMsg, rawRecvPubKey, authSecret));

   const string msg = "Test from D";
   const ubyte[] encrypted = eceEncrypt(msg, rawRecvPubKey, authSecret);
   string plaintext = cast(string) eceDecrypt(encrypted, rawRecvPrivKey, authSecret);
   assert(plaintext == msg);
}

/**
* Take in a PEM formatted key and return a uncompressed form [X9.62],
* base64url encoded key
*/
string pemPubKeyToX962Base64(string pemPublicKey) {
   
   // translate into single line
   auto sb = appender!string();
   foreach (line; pemPublicKey.split('\n')) {
      const string l = line.strip();
      // remove the “-----BEGIN PUBLIC KEY------” and “-----END PUBLIC KEY-----” lines
      if (l.startsWith(PEM_COMMENT) && l.endsWith(PEM_COMMENT)) {
         continue;
      }
      sb ~= l;
   }

   // Decode base64 and take only the last 65 bytes
   // (Public keys are 65 bytes long.)
   const ubyte[] pubKeyBytes = Base64.decode(sb.data);
   enforce(pubKeyBytes.length > PUB_KEY_BYTE_L, "Key data too large");
   const ubyte[] slice = pubKeyBytes[$-PUB_KEY_BYTE_L..$];

   // re-encode into URL safe base64 with no padding
   return Base64URLNoPadding.encode(slice);
}

unittest { // test pemPubKeyToX962Base64()
   const string pemPublicKey = readText("testdata/testkey_public.pem");
   const string k = pemPubKeyToX962Base64(pemPublicKey);
   assert(k == "BOr2OAdZHjl4rRv94xf4fqUL4gwezafIETLtEDkfqdNANdkXo6_AQXFZUXLpmaDH2HqBVnQMqM1xEdUK1wh3iu4");
}

/**
* Return the Authorization header required for web push
*/
string createAuthHeader(in ref PushSubscription sub, string contact, WebPushKeys keys) {
   JSONValue jwtPayload;
   jwtPayload["aud"] = hostFromUrl(sub.endpoint);
   jwtPayload["exp"] = (Clock.currTime(UTC()) + dur!"hours"(12)).toUnixTime();
   jwtPayload["sub"] = "mailto:" ~ contact;

   // ES256 = ECDSA using the P-256 curve and the SHA-256 hash algorithm"
   string jwt = jwtES256(jwtPayload, keys);
   
   // The k parameter must be in X9.62 encoding and Base64URL RFC7515 encoded
   return format("vapid t=%s, k=%s", jwt, keys.rawPublicKey);
}

private string hostFromUrl(string url) {
   import vibe.vibe : URL;
   URL u = URL.fromString(url);
   return format("%s://%s", u.schema, u.host);
}

unittest { // test hostFromUrl()
   const string fullUrl = "https://updates.push.services.mozilla.com/wpush/v2/blah";
   assert(hostFromUrl(fullUrl) == "https://updates.push.services.mozilla.com");
   assert(hostFromUrl("https://updates.push.services.mozilla.com") == "https://updates.push.services.mozilla.com");
}

/**
* Generates a keypair for HTTP encrypted-content-encoding Encryption
*/
EceKeySet generateKeys() {
   EceKeySet keys;

   const int err = ece_webpush_generate_keys(
      keys.prvKey.ptr, ECE_WEBPUSH_PRIVATE_KEY_LENGTH, keys.pubKey.ptr,
      ECE_WEBPUSH_PUBLIC_KEY_LENGTH, keys.authSecret.ptr, ECE_WEBPUSH_AUTH_SECRET_LENGTH);
   if (err != ECE_OK) {
      throw new CryptoException(format("Failed to generate keys. Err code %d", err));
   }

   return keys;
}

unittest { // test generateKeys();
   EceKeySet keys = generateKeys();
   // should be able to encrypt with the generated keys
   eceEncrypt("bob", keys.pubKey, keys.authSecret);
}

/**
* Generate a signed JWT for web push authorization
* jwtPayload = sub, aud, exp are the required JWT claims
*/
string jwtES256(ref JSONValue jwtPayload, WebPushKeys keys) {
   // The webpush specification dictates ES256 is to be used
   static enum JWT_HEADER = format("{\"typ\":\"JWT\",\"alg\":\"%s\"}", JWT_ALG);
   
   auto sb = appender!string();
   sb.reserve(400);
   sb ~= Base64URLNoPadding.encode(cast(ubyte[]) JWT_HEADER);
   sb ~= ".";
   sb ~= Base64URLNoPadding.encode(cast(ubyte[]) jwtPayload.toString());

   // Calculate the JWT ES256 signature
   // ES256 = ECDSA using the NIST P-256 curve [FIPS186] and the SHA-256 hash algorithm
   const string unsignedToken = sb.data;
   ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
   SHA256(cast(const(ubyte)*) unsignedToken.ptr, unsignedToken.length, hash.ptr);

   ECDSA_SIG* sig = ECDSA_do_sign(hash.ptr, SHA256_DIGEST_LENGTH, keys.ecPrivateKey);
   enforce(!(sig is null), "Digest sign failed.");
   scope(exit) ECDSA_SIG_free(sig);

   // the signature is 32 bytes of r followed by 32 bytes of s
   const auto r_len = BN_num_bytes(sig.r);
   const auto s_len = BN_num_bytes(sig.s);
   ubyte[64] sign;
   BN_bn2bin(sig.r, sign[(32-r_len)..r_len].ptr);
   BN_bn2bin(sig.s, sign[(64-s_len)..$].ptr);
   
   // add signature to JWT
   sb ~= ".";
   sb ~= Base64URLNoPadding.encode(sign);

   return sb.data;
}

private EC_KEY* loadESPrivateKey(uint curve_type, string key) {

   EC_GROUP* curve = EC_GROUP_new_by_curve_name(curve_type);
   enforce(curve != null, "Unsupported curve");
   scope(exit) EC_GROUP_free(curve);

   BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
   enforce(!(bpo is null),"Can't load the key");
   scope(exit) BIO_free(bpo);

   EVP_PKEY* pktmp = PEM_read_bio_PrivateKey(bpo, null, null, null);
   enforce(!(pktmp is null),"Can't load the evp_pkey");
   scope(exit) EVP_PKEY_free(pktmp);

   EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pktmp);
   enforce(!(eckey is null),"Can't convert evp_pkey to EC_KEY.");

   scope(failure) EC_KEY_free(eckey);
   int rc = EC_KEY_set_group(eckey, curve);
   enforce(rc == 1, "Can't associate group with the key.");

   return eckey;
}

private EC_KEY* loadESPublicKey(uint curve_type, string key) {

   EC_GROUP* curve = EC_GROUP_new_by_curve_name(curve_type);
   enforce(curve != null, "Unsupported curve");
   scope(exit) EC_GROUP_free(curve);

   BIO* bpo = BIO_new_mem_buf(cast(char*) key.ptr, -1);
   enforce(!(bpo is null), "Can't load the key");
   scope(exit) BIO_free(bpo);

   EC_KEY* eckey = PEM_read_bio_EC_PUBKEY(bpo, null, null, null);
   scope(failure) EC_KEY_free(eckey);

   int rc = EC_KEY_set_group(eckey, curve);
   enforce(rc == 1, "Can't associate group with the key.");

   rc = EC_KEY_check_key(eckey);
   enforce(rc != 0, "Public key is not valid.");

   return eckey;
}

unittest { // test JWT for webpush jwtES256()
   const string pemPublicKey = readText("testdata/testkey_public.pem");
   const string pemPrivateKey = readText("testdata/testkey_private.pem");

   // Should be able to load the keys
   WebPushKeys keys = new WebPushKeys(pemPrivateKey,pemPublicKey);

   JSONValue jwtPayload;
   jwtPayload["aud"] = "https://updates.push.services.mozilla.com";
   jwtPayload["exp"] = (Clock.currTime(UTC()) + dur!"hours"(12)).toUnixTime();
   jwtPayload["sub"] = "mailto:webpush@example.com";

   const string jwt = jwtES256(jwtPayload, keys);
   assert(jwt.length > 0);
   // Need a JWT verification function for a more complete test
}

