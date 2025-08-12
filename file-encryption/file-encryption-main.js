import {
    encryptWithPassword,
    decryptWithPassword,
    packEncryptedData,
    parseEncryptedPackage,
    packEncryptedDataToBytes,
    parseEncryptedBytes,
} from "../modules/lib.js";

(function () {})();

const DEFAULT_FILENAME = "a.part";

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];

const MAX_MIME_TYPE_BYTESIZE = 255; // 255 ascii characters in utf-8 is 255 bytes
const MAX_FILENAME_BYTESIZE = 255;
const PAD_BYTE = 0x20; // whitespace

const MIME_TYPE_OFFSET = 0;
const FILENAME_OFFSET = MAX_MIME_TYPE_BYTESIZE;
const CONTENT_OFFSET = FILENAME_OFFSET + MAX_FILENAME_BYTESIZE;

function formatFileSize(fileSize) {
    const exponent = Math.min(
        Math.floor(Math.log(fileSize) / Math.log(1024)),
        UNITS.length - 1
    );
    const approx = fileSize / 1024 ** exponent;
    const output =
        exponent === 0
            ? `${fileSize} bytes`
            : `${approx.toFixed(2)} ${UNITS[exponent]}`; // (${fileSize} bytes)`;
    return output;
}

function file2string(file) {
    return `File(name=${file.name}, size=${formatFileSize(file.size)}, type=${
        file.type
    })`;
}

// crop/pad string into fixed-size uint8array byte array
function fitStringIntoBytes(string, targetByteSize, padByte) {
    const encoder = new TextEncoder();
    const originalBytes = encoder.encode(string); // utf-8
    const bytes = new Uint8Array(targetByteSize);
    bytes.set(originalBytes.slice(0, targetByteSize), 0);
    let padStart = originalBytes.length;
    // find last non-damaged character (checking each code point)
    // non-starting code points in utf-8 have first 2 bits "10"
    while (
        padStart > 0 &&
        (bytes[padStart - 1] & 0b1100_0000) === 0b1000_0000
    ) {
        padStart -= 1;
    }
    for (let i = padStart; i < targetByteSize; i++) {
        bytes[i] = padByte;
    }
    return bytes;
}

function decodeStringFromBytes(byteArray, padByte) {
    let padStart = byteArray.length;
    while (padStart > 0 && byteArray[padStart - 1] === padByte) {
        padStart -= 1;
    }
    const decoder = new TextDecoder();
    const string = decoder.decode(byteArray.slice(0, padStart));
    return string;
}

function addFilePreview(file, previewDiv) {
    document.querySelectorAll(".image-preview").forEach((e) => e.remove());
    if (file.type.startsWith("image/")) {
        const img = document.createElement("img");
        img.classList.add("image-preview");
        img.file = file;
        previewDiv.appendChild(img);
        const reader = new FileReader();
        reader.onload = (e) => {
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
}

const passwordInput = document.getElementById("password-input");
const encryptButton = document.getElementById("encrypt-button");
const decryptButton = document.getElementById("decrypt-button");
const plainFile = document.getElementById("plain-file");
const plainFileInput = document.getElementById("plain-file-input");
const plainFileInputLabel = document.getElementById("plain-file-input-label");
const plainFileLink = document.getElementById("plain-file-link");
const previewRoot = document.getElementById("plain-file-preview");
const encryptedFile = document.getElementById("encrypted-file");
const encryptedFileInput = document.getElementById("encrypted-file-input");
const encryptedFileInputLabel = document.getElementById(
    "encrypted-file-input-label"
);
const encryptedFileLink = document.getElementById("encrypted-file-link");

function onNewPlainFile(file) {
    console.log("new plain file: " + file2string(file));
    if (encryptedFileLink.style.display === "block") {
        encryptedFileLink.style.display = "none";
        URL.revokeObjectURL(encryptedFileLink.href);
    }
    plainFileInputLabel.textContent = `Select file: "${
        file.name
    }" | ${formatFileSize(file.size)}`;
    addFilePreview(file, previewRoot);
    file.arrayBuffer()
        .then((buffer) => {
            const encoder = new TextEncoder();
            const mimeTypeBytes = fitStringIntoBytes(
                file.type,
                MAX_MIME_TYPE_BYTESIZE,
                PAD_BYTE
            );
            const filenameBytes = fitStringIntoBytes(
                file.name,
                MAX_FILENAME_BYTESIZE,
                PAD_BYTE
            );
            const contentBytes = new Uint8Array(buffer);
            const bytes = new Uint8Array(
                MAX_MIME_TYPE_BYTESIZE +
                    MAX_FILENAME_BYTESIZE +
                    contentBytes.length
            );
            bytes.set(mimeTypeBytes, MIME_TYPE_OFFSET);
            bytes.set(filenameBytes, FILENAME_OFFSET);
            bytes.set(contentBytes, CONTENT_OFFSET);
            const password = passwordInput.value;
            return encryptWithPassword(password, bytes);
        })
        .then((encryptedData) => {
            const data = packEncryptedDataToBytes(encryptedData);
            const blob = new Blob([data], { type: "application/octet-stream" });
            const url = URL.createObjectURL(blob);
            encryptedFileLink.href = url;
            encryptedFileLink.download = DEFAULT_FILENAME;
            encryptedFileLink.style.display = "block";
            plainFileLink.style.display = "none";
            console.log("prepared encrypted download link");
        });
}

function onNewEncryptedFile(file) {
    console.log("new encrypted file: " + file2string(file));
    if (plainFileLink.style.display === "block") {
        plainFileLink.style.display = "none";
        URL.revokeObjectURL(plainFileLink.href);
    }
    encryptedFileInputLabel.textContent = `Select encrypted file: "${
        file.name
    }" | ${formatFileSize(file.size)}`;
    file.arrayBuffer()
        .then((buffer) => {
            // add filename
            const bytes = new Uint8Array(buffer);
            const encryptedData = parseEncryptedBytes(bytes);
            const password = passwordInput.value;
            return decryptWithPassword(password, encryptedData);
        })
        .then((decryptedBytes) => {
            const mimeType = decodeStringFromBytes(
                decryptedBytes.slice(MIME_TYPE_OFFSET, FILENAME_OFFSET),
                PAD_BYTE
            );
            const filename = decodeStringFromBytes(
                decryptedBytes.slice(FILENAME_OFFSET, CONTENT_OFFSET),
                PAD_BYTE
            );
            const contentBytes = decryptedBytes.slice(CONTENT_OFFSET);
            // NOTE: mime type CAN alter original file extension (e.g. jpeg->jpg)
            const blob = new Blob([contentBytes], {
                type: mimeType,
                // type: "application/octet-stream",
            });
            const url = URL.createObjectURL(blob);
            plainFileLink.href = url;
            plainFileLink.download = filename;
            plainFileLink.style.display = "block";
            const file = new File([blob], filename, { type: blob.type });
            addFilePreview(file, previewRoot);
            encryptedFileLink.style.display = "none";
            console.log("prepared decrypted download link");
        });
}

encryptButton.addEventListener("click", function () {
    onNewPlainFile(plainFileInput.files[0]);
});

decryptButton.addEventListener("click", function () {
    onNewEncryptedFile(encryptedFileInput.files[0]);
});

plainFile.addEventListener(
    "dragenter",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
    },
    false
);
plainFile.addEventListener(
    "dragover",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
    },
    false
);
plainFile.addEventListener(
    "drop",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
        const files = e.dataTransfer.files;
        plainFileInput.files = files;
        const file = files[0];
        console.log("drag-dropped " + file2string(file));
        onNewPlainFile(file);
    },
    false
);

plainFileInput.addEventListener(
    "change",
    () => {
        const file = plainFileInput.files[0];
        console.log("up " + file2string(file));
        onNewPlainFile(file);
    },
    false
);

encryptedFile.addEventListener(
    "dragenter",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
    },
    false
);
encryptedFile.addEventListener(
    "dragover",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
    },
    false
);
encryptedFile.addEventListener(
    "drop",
    (e) => {
        e.stopPropagation();
        e.preventDefault();
        const files = e.dataTransfer.files;
        encryptedFileInput.files = files;
        const file = files[0];
        console.log("drag-dropped " + file2string(file));
        onNewEncryptedFile(file);
    },
    false
);

encryptedFileInput.addEventListener(
    "change",
    () => {
        const file = encryptedFileInput.files[0];
        console.log("up " + file2string(file));
        onNewEncryptedFile(file);
    },
    false
);
