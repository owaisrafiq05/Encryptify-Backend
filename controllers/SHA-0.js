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
  // Convert the string into a message array of bytes (ASCII encoding)
  const message = Array.from(text).map(char => char.charCodeAt(0));
  const messageLength = message.length;
  const bitLength = messageLength * 8; // Total bit length of the message

  // Step 1: Padding the message
  message.push(0x80); // Append a single '1' bit (0x80 in hexadecimal)

  // Step 2: Padding with 0s until length is 56 modulo 64
  while (message.length % 64 !== 56) {
    message.push(0x00); // Append 0x00 to make the length 56 modulo 64
  }

  // Step 3: Append the 64-bit message length (in big-endian format)
  for (let i = 7; i >= 0; i--) {
    message.push((bitLength >>> (i * 8)) & 0xFF); // Append length in 8-byte chunks
  }

  // Initial hash values (H0, H1, H2, H3, H4)
  let H0 = 0x67452301;
  let H1 = 0xEFCDAB89;
  let H2 = 0x98BADCFE;
  let H3 = 0x10325476;
  let H4 = 0xC3D2E1F0;

  // Process each 512-bit chunk (64 bytes)
  for (let i = 0; i < message.length; i += 64) {
    // Create the message schedule array (W[0..79])
    let W = new Array(80);

    // Fill the first 16 words of the schedule
    for (let t = 0; t < 16; t++) {
      W[t] = (message[i + 4 * t] << 24) | // Big-endian format (4 bytes = 1 word)
             (message[i + 4 * t + 1] << 16) |
             (message[i + 4 * t + 2] << 8) |
             message[i + 4 * t + 3];
    }

    // Extend the message schedule (W[16..79])
    for (let t = 16; t < 80; t++) {
      W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]; // XOR previous words
      W[t] = (W[t] << 1) | (W[t] >>> 31); // Left rotate by 1
    }

    // Initialize the working variables
    let a = H0;
    let b = H1;
    let c = H2;
    let d = H3;
    let e = H4;

    // Main loop (80 rounds)
    for (let t = 0; t < 80; t++) {
      let TEMP;
      if (t < 20) {
        // f = (b & c) | (~b & d)
        TEMP = ((a << 5) | (a >>> 27)) + ((b & c) | (~b & d)) + e + 0x5A827999 + W[t];
      } else if (t < 40) {
        // f = b ^ c ^ d
        TEMP = ((a << 5) | (a >>> 27)) + (b ^ c ^ d) + e + 0x6ED9EBA1 + W[t];
      } else if (t < 60) {
        // f = (b & c) | (b & d) | (c & d)
        TEMP = ((a << 5) | (a >>> 27)) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + W[t];
      } else {
        // f = b ^ c ^ d
        TEMP = ((a << 5) | (a >>> 27)) + (b ^ c ^ d) + e + 0xCA62C1D6 + W[t];
      }

      // Update the variables
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2); // Left rotate b by 30 bits
      b = a;
      a = TEMP >>> 0; // Ensure 32-bit value
    }

    // Update the hash values
    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
  }

  // Step 4: Produce the final hash by concatenating H0, H1, H2, H3, H4
  const hash = [H0, H1, H2, H3, H4].map(h => 
    h.toString(16).padStart(8, '0')
  ).join('');

  return hash;
};
