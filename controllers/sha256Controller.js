// SHA-256 hash function
const sha256 = (message) => {
    const bytesToHex = (bytes) => bytes.map(byte => ('0' + byte.toString(16)).slice(-2)).join('');
    const stringToBytes = (str) => Array.from(unescape(encodeURIComponent(str))).map(c => c.charCodeAt(0));
  
    const K = [];
    (function initializeConstants() {
      const isPrime = (n) => {
        const sqrtN = Math.sqrt(n);
        for (let factor = 2; factor <= sqrtN; factor++) {
          if (!(n % factor)) return false;
        }
        return true;
      };
  
      const getFractionalBits = (n) => ((n - (n | 0)) * 0x100000000) | 0;
      let n = 2, nPrime = 0;
      while (nPrime < 64) {
        if (isPrime(n)) {
          K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
          nPrime++;
        }
        n++;
      }
    })();
  
    const bytesToWords = (bytes) => {
      const words = [];
      for (let i = 0, b = 0; i < bytes.length; i++, b += 8) {
        words[b >>> 5] |= bytes[i] << (24 - b % 32);
      }
      return words;
    };
  
    const wordsToBytes = (words) => {
      const bytes = [];
      for (let b = 0; b < words.length * 32; b += 8) {
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
      }
      return bytes;
    };
  
    const processBlock = (H, M, offset) => {
      const W = [];
      let [a, b, c, d, e, f, g, h] = H;
  
      for (let i = 0; i < 64; i++) {
        if (i < 16) {
          W[i] = M[offset + i] | 0;
        } else {
          const gamma0x = W[i - 15];
          const gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^
                         ((gamma0x << 14) | (gamma0x >>> 18)) ^
                         (gamma0x >>> 3);
  
          const gamma1x = W[i - 2];
          const gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                         ((gamma1x << 13) | (gamma1x >>> 19)) ^
                         (gamma1x >>> 10);
  
          W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
        }
  
        const ch = (e & f) ^ (~e & g);
        const maj = (a & b) ^ (a & c) ^ (b & c);
  
        const sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
        const sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));
  
        const t1 = h + sigma1 + ch + K[i] + W[i];
        const t2 = sigma0 + maj;
  
        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
      }
  
      H[0] = (H[0] + a) | 0;
      H[1] = (H[1] + b) | 0;
      H[2] = (H[2] + c) | 0;
      H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0;
      H[5] = (H[5] + f) | 0;
      H[6] = (H[6] + g) | 0;
      H[7] = (H[7] + h) | 0;
    };
  
    const H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
  
    const messageBytes = stringToBytes(message);
    const m = bytesToWords(messageBytes);
    const l = messageBytes.length * 8;
  
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = l;
  
    for (let i = 0; i < m.length; i += 16) {
      processBlock(H, m, i);
    }
  
    return bytesToHex(wordsToBytes(H));
  };
  
  // Hash Controller
  export const hashController = async (request, response) => {
    const { text } = request.body;
  
    if (!text) {
      response.json({
        message: "Text is required.",
        status: false,
      });
      return;
    }
  
    try {
      const hash = sha256(text);
      response.json({
        hash,
        message: "Hashing successful.",
        status: true,
      });
    } catch (error) {
      response.json({
        message: "Hashing failed.",
        status: false,
        data: error.message,
      });
    }
  };
  