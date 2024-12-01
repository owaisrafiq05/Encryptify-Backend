export class BitArray {
  constructor(length) {
      if (typeof length === 'number') {
          this.bits = new Array(length).fill(0);
      } else if (Array.isArray(length)) {
          this.bits = [...length];
      } else if (length instanceof BitArray) {
          this.bits = [...length.bits];
      } else if (typeof length === 'string') {
          this.bits = length.split('').map(bit => parseInt(bit));
      } else {
          throw new Error('Invalid BitArray constructor argument');
      }
  }

  get length() {
      return this.bits.length;
  }

  get(index) {
      if (index < 0 || index >= this.length) {
          throw new Error('Index out of bounds');
      }
      return this.bits[index];
  }

  set(index, value) {
      if (index < 0 || index >= this.length) {
          throw new Error('Index out of bounds');
      }
      this.bits[index] = value ? 1 : 0;
  }

  copy() {
      return new BitArray(this.bits);
  }

  slice(start, end) {
      if (start < 0 || start >= this.length || (end !== undefined && (end < 0 || end > this.length))) {
          throw new Error('Invalid slice bounds');
      }
      return new BitArray(this.bits.slice(start, end));
  }

  concat(other) {
      if (!(other instanceof BitArray)) {
          throw new Error('Can only concatenate with another BitArray');
      }
      return new BitArray(this.bits.concat(other.bits));
  }

  xor(other) {
      if (!(other instanceof BitArray) || this.length !== other.length) {
          throw new Error('XOR requires BitArrays of equal length');
      }
      for (let i = 0; i < this.length; i++) {
          this.bits[i] ^= other.bits[i];
      }
      return this;
  }

  shiftLeft(positions, circular = false) {
      if (positions < 0 || positions > this.length) {
          throw new Error('Invalid shift amount');
      }
      
      if (circular) {
          for (let i = 0; i < positions; i++) {
              const bit = this.bits.shift();
              this.bits.push(bit);
          }
      } else {
          this.bits = [...this.bits.slice(positions), ...new Array(positions).fill(0)];
      }
      return this;
  }

  shiftRight(positions, circular = false) {
      if (positions < 0 || positions > this.length) {
          throw new Error('Invalid shift amount');
      }
      
      if (circular) {
          for (let i = 0; i < positions; i++) {
              const bit = this.bits.pop();
              this.bits.unshift(bit);
          }
      } else {
          this.bits = [...new Array(positions).fill(0), ...this.bits.slice(0, this.length - positions)];
      }
      return this;
  }

  toString() {
      return this.bits.join('');
  }

  toNumber() {
      return parseInt(this.toString(), 2);
  }

  static generateRandom(length) {
      if (length <= 0 || !Number.isInteger(length)) {
          throw new Error('Length must be a positive integer');
      }
      const result = new BitArray(length);
      for (let i = 0; i < length; i++) {
          result.set(i, Math.random() < 0.5);
      }
      return result;
  }

  static fromNumber(num, length) {
      if (!Number.isInteger(num) || num < 0) {
          throw new Error('Number must be a non-negative integer');
      }
      if (length <= 0 || !Number.isInteger(length)) {
          throw new Error('Length must be a positive integer');
      }
      if (num >= Math.pow(2, length)) {
          throw new Error('Number is too large for specified bit length');
      }
      
      const result = new BitArray(length);
      for (let i = length - 1; i >= 0; i--) {
          result.set(i, num & 1);
          num >>= 1;
      }
      return result;
  }

  static fromBinaryString(binaryString) {
      if (!/^[01]+$/.test(binaryString)) {
          throw new Error('Invalid binary string');
      }
      return new BitArray(binaryString);
  }

  static fromHexString(hexString) {
      if (!/^[0-9A-Fa-f]+$/.test(hexString)) {
          throw new Error('Invalid hexadecimal string');
      }
      const binaryString = hexString
          .split('')
          .map(char => parseInt(char, 16).toString(2).padStart(4, '0'))
          .join('');
      return new BitArray(binaryString);
  }

  toHexString() {
      const paddedBits = this.bits.length % 4 === 0 
          ? this.bits 
          : [...this.bits, ...new Array(4 - (this.bits.length % 4)).fill(0)];
      
      let hexString = '';
      for (let i = 0; i < paddedBits.length; i += 4) {
          const nibble = paddedBits.slice(i, i + 4).join('');
          hexString += parseInt(nibble, 2).toString(16).toUpperCase();
      }
      return hexString;
  }

  equals(other) {
      if (!(other instanceof BitArray) || this.length !== other.length) {
          return false;
      }
      return this.bits.every((bit, index) => bit === other.bits[index]);
  }

  and(other) {
      if (!(other instanceof BitArray) || this.length !== other.length) {
          throw new Error('AND requires BitArrays of equal length');
      }
      const result = new BitArray(this.length);
      for (let i = 0; i < this.length; i++) {
          result.set(i, this.get(i) & other.get(i));
      }
      return result;
  }

  or(other) {
      if (!(other instanceof BitArray) || this.length !== other.length) {
          throw new Error('OR requires BitArrays of equal length');
      }
      const result = new BitArray(this.length);
      for (let i = 0; i < this.length; i++) {
          result.set(i, this.get(i) | other.get(i));
      }
      return result;
  }

  not() {
      const result = new BitArray(this.length);
      for (let i = 0; i < this.length; i++) {
          result.set(i, this.get(i) ? 0 : 1);
      }
      return result;
  }

  reverseOrder() {
      const result = new BitArray(this.length);
      for (let i = 0; i < this.length; i++) {
          result.set(i, this.get(this.length - 1 - i));
      }
      return result;
  }

  countOnes() {
      return this.bits.reduce((count, bit) => count + bit, 0);
  }

  countZeros() {
      return this.length - this.countOnes();
  }
}

export default BitArray;