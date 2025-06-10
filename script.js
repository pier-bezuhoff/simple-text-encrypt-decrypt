function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const CHUNK = 0x8000;
    const chunks = [];
    for (let i = 0; i < bytes.length; i += CHUNK) {
        const chunk = bytes.subarray(i, i + CHUNK);
        chunks.push(String.fromCharCode.apply(null, chunk));
    }
    return btoa(chunks.join(""));
}

// why this one isn't chunked?
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 16; // 128 bits
const IV_LENGTH = 12; // 96 bits

const SALT_OFFSET = 0;
const IV_OFFSET = SALT_LENGTH;
const CIPHERTEXT_OFFSET = IV_OFFSET + IV_LENGTH;

// passphrase and plaintext can be any UTF-8
// -> encryptedData = { salt, iv, ciphertext: Uint8Array }
async function encryptWithPassword(passphrase, plaintext) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    // Derive key
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );
    // Encrypt data
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(plaintext) // Unicode -> UTF-8 bytes
    );
    return {
        salt: salt,
        iv: iv,
        ciphertext: new Uint8Array(ciphertext),
    };
}

// encryptedData is supposed to be the same format as encryptWithPassword output:
// encryptedData = { salt, iv, ciphertext: Uint8Array }
async function decryptWithPassword(passphrase, encryptedData) {
    const salt = encryptedData.salt;
    const iv = encryptedData.iv;
    const ciphertext = encryptedData.ciphertext;
    // Derive key
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
    // Decrypt data
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted); // UTF-8 bytes -> Unicode
}

// -> encryptedPackage: base64 string
function packEncryptedData(encryptedData) {
    const { salt, iv, ciphertext } = encryptedData;
    const package = new Uint8Array(salt.length + iv.length + ciphertext.length);
    package.set(salt, SALT_OFFSET);
    package.set(iv, IV_OFFSET);
    package.set(ciphertext, CIPHERTEXT_OFFSET);
    return arrayBufferToBase64(package.buffer);
}

// -> encryptedData = { salt, iv, ciphertext: Uint8Array }
function parseEncryptedPackage(encryptedPackage) {
    const packageBytes = new Uint8Array(base64ToArrayBuffer(encryptedPackage));
    const salt = packageBytes.slice(SALT_OFFSET, IV_OFFSET);
    const iv = packageBytes.slice(IV_OFFSET, CIPHERTEXT_OFFSET);
    const ciphertext = packageBytes.slice(CIPHERTEXT_OFFSET);
    return {
        salt: salt,
        iv: iv,
        ciphertext: ciphertext,
    };
}

document.addEventListener("DOMContentLoaded", function () {
    const passwordInput = document.getElementById("password-input");
    const encryptButton = document.getElementById("encrypt-button");
    const decryptButton = document.getElementById("decrypt-button");
    const plainText = document.getElementById("plain-text");
    const cipherText = document.getElementById("cipher-text");
    encryptButton.addEventListener("click", function () {
        const password = passwordInput.value;
        const text = plainText.value;
        cipherText.value = "encrypting...";
        encryptWithPassword(password, text)
            .then((encryptedData) => {
                cipherText.value = packEncryptedData(encryptedData);
            })
            .catch((e) => {
                console.error(e);
                cipherText.value = "Failed to encrypt: " + e;
            });
    });
    decryptButton.addEventListener("click", function () {
        const password = passwordInput.value;
        const ciphertext = cipherText.value;
        plainText.value = "decrypting...";
        const encryptedData = parseEncryptedPackage(ciphertext);
        decryptWithPassword(password, encryptedData)
            .then((decryptedText) => {
                plainText.value = decryptedText;
            })
            .catch((e) => {
                console.error(e);
                plainText.value =
                    "Failed to decrypt: incorrect password or corrupted ciphertext!";
            });
    });
});
