/**
 * Fortress // Cryptography & Hashing Module
 */

document.addEventListener('DOMContentLoaded', () => {
    const hashInput = document.getElementById('hash-input');
    const md5Output = document.getElementById('output-md5');
    const sha1Output = document.getElementById('output-sha1');
    const sha256Output = document.getElementById('output-sha256');
    const sha512Output = document.getElementById('output-sha512');

    const kdfSlider = document.getElementById('kdf-rounds-slider');
    const kdfVal = document.getElementById('kdf-rounds-val');
    const kdfBtn = document.getElementById('btn-benchmark-kdf');
    const kdfDelay = document.getElementById('kdf-stat-delay');
    const kdfAttacker = document.getElementById('kdf-stat-attacker');

    // 1. Live Hash Avalanche visualizer
    hashInput.addEventListener('input', async () => {
        const text = hashInput.value;
        
        if (text.length === 0) {
            md5Output.textContent = "d41d8cd98f00b204e9800998ecf8427e";
            sha1Output.textContent = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
            sha256Output.textContent = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            sha512Output.textContent = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
            
            md5Output.classList.remove('active');
            sha1Output.classList.remove('active');
            sha256Output.classList.remove('active');
            sha512Output.classList.remove('active');
            return;
        }

        md5Output.classList.add('active');
        sha1Output.classList.add('active');
        sha256Output.classList.add('active');
        sha512Output.classList.add('active');

        // MD5 (JS compact implementation)
        md5Output.textContent = calcMD5(text);

        // Native Async Web Crypto for SHA family
        try {
            sha1Output.textContent = await hashWebCrypto("SHA-1", text);
            sha256Output.textContent = await hashWebCrypto("SHA-256", text);
            sha512Output.textContent = await hashWebCrypto("SHA-512", text);
        } catch (err) {
            console.error("Cryptographic hashing failed: ", err);
        }
    });

    // 2. KDF Simulator
    kdfSlider.addEventListener('input', () => {
        kdfVal.textContent = parseInt(kdfSlider.value).toLocaleString();
    });

    kdfBtn.addEventListener('click', async () => {
        kdfBtn.disabled = true;
        kdfBtn.textContent = "Deriving key stretched bytes...";
        kdfDelay.textContent = "Computing...";
        kdfAttacker.textContent = "Calculating...";

        const iterations = parseInt(kdfSlider.value);
        
        // Short timeout to let UI update before thread block (Web Crypto can block slightly)
        setTimeout(async () => {
            try {
                const passwordText = "FortressPassStretchingBenchmark123!";
                const saltText = "FortressSalt123!Stretching";
                
                const enc = new TextEncoder();
                const pwBuf = enc.encode(passwordText);
                const saltBuf = enc.encode(saltText);

                const start = performance.now();
                
                // Import raw password as key
                const baseKey = await crypto.subtle.importKey(
                    "raw", pwBuf, "PBKDF2", false, ["deriveBits"]
                );

                // Perform real PBKDF2 stretching in browser
                await crypto.subtle.deriveBits(
                    {
                        name: "PBKDF2",
                        salt: saltBuf,
                        iterations: iterations,
                        hash: "SHA-256"
                    },
                    baseKey,
                    256
                );
                
                const end = performance.now();
                const duration = end - start;

                // Render metrics
                kdfDelay.textContent = `${duration.toFixed(2)} ms`;
                
                // Attacker benchmark: An RTx 4090 card gets approx 25 Billion SHA-256 / sec.
                // Stretched PBKDF2 scales inversely with iterations count.
                const rawGpuSpeed = 25000000000; // 25 Giga-hashes/sec
                const stretchedSpeed = rawGpuSpeed / iterations;
                
                kdfAttacker.textContent = `${Math.ceil(stretchedSpeed).toLocaleString()} H/s`;

                // Quick visual feedback on delay usability
                if (duration > 350) {
                    kdfDelay.style.color = "var(--strength-1)"; // Noticeable lag
                } else if (duration > 100) {
                    kdfDelay.style.color = "var(--strength-3)"; // Solid security
                } else {
                    kdfDelay.style.color = "var(--strength-4)"; // Excellent response
                }
            } catch (err) {
                console.error("PBKDF2 Key Derivation failed: ", err);
                kdfDelay.textContent = "Error";
                kdfAttacker.textContent = "Error";
            } finally {
                kdfBtn.disabled = false;
                kdfBtn.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                    Run KDF Stretching Benchmark
                `;
            }
        }, 50);
    });
});

/**
 * Web Crypto standard SHA digest utility
 */
async function hashWebCrypto(algorithm, text) {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Ultra-compact standard MD5 implementation in pure JavaScript
 */
function calcMD5(str) {
    var k = [], i = 0;
    for (; i < 64; ) k[i] = 0 | Math.sin(++i) * 4294967296;
    var b = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        a = (function(str) {
            var i = 0, words = [];
            for (; i < str.length * 8; i += 8) {
                words[i >> 5] |= (str.charCodeAt(i / 8) & 255) << (i % 32);
            }
            return words;
        })(str + "\x80");
    a[i = (((str.length + 8) >> 6) + 1) * 16 - 9] = str.length * 8;
    for (i = 0; i < a.length; i += 16) {
        var c = b.slice(0), j = 0;
        for (; j < 64; ) {
            var d = [
                function(x, y, z) { return (x & y) | (~x & z); },
                function(x, y, z) { return (x & z) | (y & ~z); },
                function(x, y, z) { return x ^ y ^ z; },
                function(x, y, z) { return y ^ (x | ~z); }
            ][j >> 4](b[1], b[2], b[3]);
            d = b[3] + d + k[j] + (a[i + [
                j, 5 * j + 1, 3 * j + 5, 7 * j
            ][j >> 4] % 16] | 0);
            b = [
                d + (b[0] = b[3]),
                b[1] + ((d = b[0] + d) << (j = [
                    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21
                ][(j >> 4) * 4 + (j++ % 4)]) | (d >>> (32 - j))),
                b[1],
                b[2]
            ];
        }
        for (var j = 0; j < 4; ) b[j] = (b[j] + c[j++]) | 0;
    }
    for (var out = "", j = 0; j < 32; ) {
        out += ((b[j >> 3] >> ((j++ & 7) * 4 + 4)) & 15).toString(16) +
               ((b[j >> 3] >> ((j & 7) * 4)) & 15).toString(16);
    }
    return out;
}
