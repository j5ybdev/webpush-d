# Webpushd

D library that implements [RFC8292 Spec](https://datatracker.ietf.org/doc/rfc8292/) web push.

Uses [libecec](https://github.com/web-push-libs/ecec) and openssl to encrypt web push messages.

### Usage
```d
WebPushKeys keys = new WebPushKeys(privateKeyAsPemString, publicKeyAsPemString);
WebPusher webPush = new VibeWebPusher(keys);
WebPushOptions webPushOptions;
webPushOptions.contact = "email@example.com";

// Load subscription data from a database
PushSubscription sub = {
   endpoint: "https://updates.push.services.mozilla.com/wpush/v2/blahblah...",
   keys: {
      p256dh: "BO...",
      auth: "..."
   }
};

WebPushResp resp = webPush.send(sub, "Hello from D!", webPushOptions);
```

### Install dependencies

 1. install openssl
```
sudo apt install libssl-dev
```
 2. Install [libecec](https://github.com/web-push-libs/ecec) into ./lib/ecec
 ```
 git clone https://github.com/web-push-libs/ecec
 cd ecec
 mkdir build
 cd build
 cmake  ..
 make
 sudo cp libece.a /path/to/webpush-d/lib/ecec/libece.a
  ```

### Build
```
dub build
```

### Key generation

The Library reads in keys in the PEM format

1. Create an elliptic curve private key using Openssl
`openssl ecparam -name prime256v1 -genkey -noout -out vapid_private.pem`
2. Extract public key from private key file
`openssl ec -in vapid_private.pem -pubout -out vapid_public.pem`