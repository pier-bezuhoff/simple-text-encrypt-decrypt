export {
    encryptWithPassword,
    decryptWithPassword,
    packEncryptedData,
    parseEncryptedPackage,
    packEncryptedDataToBytes,
    parseEncryptedBytes,
};

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

// password can be any UTF-8, bytes is Uint8Array (use new TextEncoder().encode(<unicode text>))
// -> encryptedData = { salt, iv, ciphertext: Uint8Array }
async function encryptWithPassword(password, bytes) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    // Derive key
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
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
        bytes
    );
    return {
        salt: salt,
        iv: iv,
        ciphertext: new Uint8Array(ciphertext),
    };
}

// encryptedData is supposed to be the same format as encryptWithPassword output:
// encryptedData = { salt, iv, ciphertext: Uint8Array }
// returns bytes: Uint8Array (decode with new TextDecoder().decode(bytes))
async function decryptWithPassword(password, encryptedData) {
    const salt = encryptedData.salt;
    const iv = encryptedData.iv;
    const ciphertext = encryptedData.ciphertext;
    // Derive key
    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
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
    return decrypted;
}

// -> encryptedPackage: base64 string
function packEncryptedData(encryptedData) {
    const { salt, iv, ciphertext } = encryptedData;
    const pkg = new Uint8Array(salt.length + iv.length + ciphertext.length);
    pkg.set(salt, SALT_OFFSET);
    pkg.set(iv, IV_OFFSET);
    pkg.set(ciphertext, CIPHERTEXT_OFFSET);
    return arrayBufferToBase64(pkg.buffer);
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

function packEncryptedDataToBytes(encryptedData) {
    const { salt, iv, ciphertext } = encryptedData;
    const pkg = new Uint8Array(salt.length + iv.length + ciphertext.length);
    pkg.set(salt, SALT_OFFSET);
    pkg.set(iv, IV_OFFSET);
    pkg.set(ciphertext, CIPHERTEXT_OFFSET);
    return pkg;
}

function parseEncryptedBytes(packageBytes) {
    const salt = packageBytes.slice(SALT_OFFSET, IV_OFFSET);
    const iv = packageBytes.slice(IV_OFFSET, CIPHERTEXT_OFFSET);
    const ciphertext = packageBytes.slice(CIPHERTEXT_OFFSET);
    return {
        salt: salt,
        iv: iv,
        ciphertext: ciphertext,
    };
}
