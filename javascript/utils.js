'use strict';
const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');

// https://en.wikipedia.org/wiki/Letter_frequency
const englishLetterFrequency = {
  e: 0.12702,
  t: 0.09056,
  a: 0.08167,
  o: 0.07507,
  i: 0.06966,
  n: 0.06749,
  s: 0.06327,
  h: 0.06094,
  r: 0.05987,
  d: 0.04253,
  l: 0.04025,
  c: 0.02782,
  u: 0.02758,
  m: 0.02406,
  w: 0.02361,
  f: 0.02228,
  g: 0.02015,
  y: 0.01974,
  p: 0.01929,
  b: 0.01492,
  v: 0.00978,
  k: 0.00772,
  j: 0.00153,
  x: 0.00150,
  q: 0.00095,
  z: 0.00074,
};

const stringLetterFrequency = string => {
  const counter = Object.assign({}, englishLetterFrequency);
  for(let key in counter) {
    counter[key] = 0;
  }
  let total = 0;
  const count = Array.prototype.reduce.call(string, (acc, letter) => {
    if(letter in acc) {
      acc[letter]++;
      total++;
    }
    return acc;
  }, counter);
  for(let key in counter) {
    counter[key] /= total;
  }

  return counter;
};

const stringError = string => {
  const freq = stringLetterFrequency(string);
  return Object.keys(freq).reduce((acc, letter) => acc + Math.abs(freq[letter] - englishLetterFrequency[letter]) , 0);
};

const makeBitString = str => Array.prototype.map.call(str, n => n.toString(2))
  .map(padBinary)
  .join('');

const hammingDistance = (a, b) => {
  let bitStringA = makeBitString(a);
  let bitStringB = makeBitString(b);
  const diff = Math.abs(bitStringA.length - bitStringB.length);

  return Array.prototype.reduce.call(bitStringA, (acc, char, i) => acc + (char !== bitStringB[i] ? 1 : 0), 0);
};

const padBinary = num => ('00000000' + num).slice(-8);
const padBase64 = num => ('000000' + num).slice(-6);

const slash = '/'.charCodeAt(0);
const plus = '+'.charCodeAt(0);
const equal = '='.charCodeAt(0);
const zero = '0'.charCodeAt(0);
const nine = '9'.charCodeAt(0);
const a = 'a'.charCodeAt(0);
const z = 'z'.charCodeAt(0);
const A = 'A'.charCodeAt(0);
const Z = 'Z'.charCodeAt(0);

const hexCharToNum = byte => {
  let rtn = 0;
  if(byte >= a) {
    rtn = byte - a + 10;
  } else {
    rtn = byte - zero;
  }

  return rtn;
};

const hexStringToBuffer = hexString => new Buffer(hexString, 'hex');
const bufferToHexString = buffer => buffer.toString('hex');
const stringToBuffer = string => new Buffer(string);

const numToBase64 = num => {
  if(num === 63) {
    return '/'
  } else if(num === 62) {
    return '+';
  } else if (num >= 52) {
    return String.fromCharCode(num + zero - 52);
  } else if (num >= 26) {
    return String.fromCharCode(num + a - 26);
  } else {
    return String.fromCharCode(num + A);
  }
};

const base64ToNum = code => {
  if(code === slash) {
    return 63;
  } else if(code == plus) {
    return 62;
  } else if(code <= nine && code >= zero) {
    return (code - zero) + 52;
  } else if(code <= z && code >= a) {
    return (code - a) + 26;
  } else if(code <= Z && code >= A) {
    return (code - A);
  } else if (code === equal) {
    return 0;
  } else {
  }
};

const readLines = filename => new Promise((resolve, reject) => {
  const fileStream = fs.createReadStream(filename);
  const lineReader = readline.createInterface({
    input: fileStream
  });
  const lines = [];
  lineReader.on('line', lines.push.bind(lines));
  lineReader.on('close', () => resolve(lines));

  lineReader.on('error', reject);
});

const readFile = (filename, encoding) => new Promise((resolve, reject) => {
  encoding = encoding || 'utf8';
  fs.readFile(filename, encoding, (err, str) => {
    if(err) { reject(err); }
    else { resolve(new Buffer(str)); }
  });
});

const writeFile = (filename, contents) => new Promise((resolve, reject) => {
  fs.writeFile(filename, contents, err => {
    if(err) { return reject(err); }
    resolve();
  })
});

const base64ToBuffer = buffer => {
  const base64Nums = Array.prototype.map.call(buffer, base64ToNum);

  const binaryString = base64Nums
    .map(s => s.toString(2))
    .map(padBase64)
    .join('');

  const nums = [];
  for(let i = 0; i < binaryString.length / 8; i++) {
    nums.push(parseInt(binaryString.slice(i*8, i*8 + 8), 2));
  }

  // remove final == and = padding numbers
  if(nums[nums.length - 1] === 0) {
    nums.pop();
  }
  if(nums[nums.length - 1] === 0) {
    nums.pop();
  }

  return new Buffer(nums);
};

const breakIntoBlocks = (buffer, blockSize) => {
  const result = [];

  for(let i = 0; i < buffer.length / blockSize; i++) {
    result.push(buffer.slice(i * blockSize, i * blockSize + blockSize));
  }

  const last = result.pop();
  result.push(new Buffer(blockSize).fill(0));
  last.copy(result[result.length - 1]);

  return result;
};

const transpose = blocks => {
  const keySize = blocks[0].length;

  const result = [];
  for(let i = 0; i < keySize; i++) {
    result.push(new Buffer(blocks.length).fill(0));
    for(let j = 0; j < blocks.length; j++) {
      result[i][j] = blocks[j][i];
    }
  }

  return result;
};

const readBase64File = (filename) => {
  return readFile(filename, 'base64');
}

const deciperBuffer = (algorithm, key, buffer) => {
  const decipher = crypto.createDecipher(algorithm, key);
  console.log(key, buffer);

  return new Promise((resolve, reject) => {
    decipher.on('error', reject);

    const enc = decipher.update(buffer);
    enc += decipher.final();
    resolve(enc);
  });
};

module.exports = {
  hexStringToBuffer,
  padBinary,
  bufferToHexString,
  stringError,
  numToBase64,
  readLines,
  readFile,
  stringToBuffer,
  hammingDistance,
  base64ToBuffer,
  transpose,
  breakIntoBlocks,
  readBase64File,
  deciperBuffer
};
