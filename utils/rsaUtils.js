
// Function to calculate the GCD
export const gcd = (a, b) => {
    if (b === 0n) return a;
    return gcd(b, a % b);
};

// Function to calculate modular inverse of e mod φ(n)
export const modInverse = (e, phi) => {
    let m0 = phi;
    let x0 = 0n;
    let x1 = 1n;

    if (gcd(e, phi) !== 1n) {
        throw new Error(`e (${e}) and phi (${phi}) are not coprime.`);
    }

    while (e > 1n) {
        const q = e / phi;
        [phi, e] = [e % phi, phi];
        [x0, x1] = [x1 - q * x0, x0];
    }

    return x1 < 0n ? x1 + m0 : x1;
};
// RSA Key Generation
export const generateKeys = () => {
    const generateRandomPrime = (min, max) => {
        const isPrime = (num) => {
            if (num < 2) return false;
            for (let i = 2; i * i <= num; i++) {
                if (num % i === 0) return false;
            }
            return true;
        };

        const primes = [];
        for (let i = min; i <= max; i++) {
            if (isPrime(i)) primes.push(i);
        }
        if (primes.length === 0) throw new Error("No primes found in the given range.");
        const randomIndex = Math.floor(Math.random() * primes.length);
        return primes[randomIndex];
    };

    let p, q;
    do {
        p = generateRandomPrime(100, 200); // Larger range for better security
        q = generateRandomPrime(100, 200);
    } while (p === q);

    const n = BigInt(p * q);
    const phi = BigInt((p - 1) * (q - 1));

    // Find e (1 < e < phi) such that gcd(e, phi) = 1
    let e = 3n;
    while (e < phi && gcd(e, phi) !== 1n) {
        e += 2n; // Ensure e is odd for efficiency
    }

    if (e >= phi) {
        throw new Error("Failed to find a suitable 'e'.");
    }

    // Calculate d (modular inverse of e)
    const d = modInverse(e, phi);

    return {
        publicKey: { e, n },
        secretKey: { d, n },
    };
};

// Encrypt/Decrypt Helpers
export const modExp = (base, exp, mod) => {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
};

export const encrypt = (m, publicKey) => {
    const { e, n } = publicKey;
    return modExp(m, e, n);
};

export const decrypt = (c, secretKey) => {
    const { d, n } = secretKey;
    return modExp(c, d, n);
};

export const encryptMessage = (message, publicKey) => {
    return message.split("").map((char) => {
        const m = BigInt(char.charCodeAt(0));
        return encrypt(m, publicKey).toString();
    });
};

export const decryptMessage = (encryptedText, secretKey) => {
    return encryptedText.map((c) => {
        const m = decrypt(BigInt(c), secretKey);
        return String.fromCharCode(Number(m));
    }).join("");
};
