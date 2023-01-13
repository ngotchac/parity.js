const secp256k1 = require("secp256k1");
const { keccak256 } = require("js-sha3");

const wordlist = require("./wordlist.json");

function bytesToHex (bytes) {
    return '0x' + Buffer.from(bytes).toString('hex');
}

function phraseToWallet (phrase) {
    const words = new Set(wordlist);
    for (const word of phrase.split(" ")) {
        if (!words.has(word)) {
            throw new Error(`Invalid word: ${word}`);
        }
    }
    let secret = keccak256.array(phrase);

    for (let i = 0; i < 16384; i++) {
        secret = keccak256.array(secret);
    }

    while (true) {
        secret = keccak256.array(secret);

        const secretBuf = Buffer.from(secret);

        if (secp256k1.privateKeyVerify(secretBuf)) {
            // No compression, slice out last 64 bytes
            const publicBuf = secp256k1.publicKeyCreate(secretBuf, false).slice(-64);
            const address = keccak256.array(publicBuf).slice(12);

            if (address[0] !== 0) {
                continue;
            }

            const wallet = {
                secret: bytesToHex(secretBuf),
                public: bytesToHex(publicBuf),
                address: bytesToHex(address)
            };

            return wallet;
        }
    }
}
