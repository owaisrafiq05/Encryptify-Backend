export const sha0Hash = (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({
      message: "Text is required for hashing.",
      status: false,
    });
  }
  try {
    const hash = sha0(text);
    res.status(200).json({
      message: "Hashing successful",
      hash: hash,
      status: true,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
      status: false,
    });
  }
};

const sha0 = (text) => {
  const utf8Bytes = new TextEncoder().encode(text);
  
  const messageLenBits = BigInt(utf8Bytes.length * 8);
  
  const paddedMessage = new Uint8Array(
    Math.ceil((utf8Bytes.length + 1 + 8) / 64) * 64
  );
  
  paddedMessage.set(utf8Bytes);
  
  paddedMessage[utf8Bytes.length] = 0x80;
  
  for (let i = 0; i < 8; i++) {
    paddedMessage[paddedMessage.length - 8 + i] = 
      Number((messageLenBits >> BigInt(56 - i * 8)) & 0xFFn);
  }

  const H = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
  ];

  const rotl = (x, n) => {
    x = x >>> 0;
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  };

  for (let i = 0; i < paddedMessage.length; i += 64) {
    const W = new Array(80).fill(0);
    
    for (let t = 0; t < 16; t++) {
      W[t] = (
        (paddedMessage[i + t * 4] << 24) |
        (paddedMessage[i + t * 4 + 1] << 16) |
        (paddedMessage[i + t * 4 + 2] << 8) |
        (paddedMessage[i + t * 4 + 3])
      ) >>> 0;
    }

    for (let t = 16; t < 80; t++) {
      W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
    }

    let [a, b, c, d, e] = H;

    for (let t = 0; t < 80; t++) {
      let f, k;
      
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      const temp = (rotl(a, 5) + f + e + k + W[t]) >>> 0;
      
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
  }

  return H.map(h => h.toString(16).padStart(8, '0')).join('');
};

export default sha0;