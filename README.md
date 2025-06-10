# Simple text encryption website
- You input password & text -> get encrypted package (salt, IV, ciphertext)
- You input password & encrypted package -> get back original text
- Unicode support (utf-8)
- Integrity detection/authenticated encryption
- Relies on [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
## Algorithm
password + 128 bit salt -> [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) (600_000 iterations) -> key  
text + key + 96 bit IV -> [GCM-AES](https://en.wikipedia.org/wiki/Galois/Counter_Mode) -> ciphertext in base64  
Encrypted text to the right is concatenated salt+IV+ciphertext.  
## Screenshot
![image](https://github.com/user-attachments/assets/9b97056c-1b54-4d89-bbd7-6972175909a6)
