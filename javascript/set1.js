'use strict';

// challenge 1 function
const hexToBase64 = hexBuffer => {
  const str = hexBuffer.reduce((acc, current) => acc + padBinary(current.toString(2)), '');
  const result = new Buffer(str.length / 6);
  result.fill(0);
  for(let i = 0; i < str.length / 6; i++) {
    const strIndex = i * 6;
    result[i] = parseInt(str.slice(strIndex, strIndex+6), 2);
  }

  return Array.prototype.map.call(result, numToBase64).join('');
};

// challenge 2 function
const fixedXor = (a, b) => {
  return new Buffer(Array.prototype.map.call(a, (n,i) => n ^ b[i]));
};

// challenge 3
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

const decryptXor = buffer => {

  /*let bytes = [];
  for(let i = 0; i < 255; i++) {
    bytes.push(i);
  }
  */
 let bytes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()'.split('')

  return bytes
    .map(character => {
      const characterBuffer = new Buffer(buffer.length);
      characterBuffer.fill(character);

      const xored = fixedXor(buffer, characterBuffer);
      const string = xored.toString();
      return { buffer: xored, error: stringError(string) };
    })
    .reduce((acc, obj) => {
      if(obj.error <= acc.error) {
        return obj;
      }
      return acc;
    }, { error: Infinity, buffer: new Buffer(buffer.length).fill(0) });
};

// challenge 5
const encryptRepeatingKeyXor = (key, string) => {
  const repeatingKeyBuffer = stringToBuffer(key.repeat(Math.ceil(string.length / key.length)));

  return fixedXor(stringToBuffer(string), repeatingKeyBuffer);
};

// utility functions
const padBinary = num => ('00000000' + num).slice(-8);

const upperA = 'A'.charCodeAt(0);
const lowerA = 'a'.charCodeAt(0);
const zero = '0'.charCodeAt(0);

const hexCharToNum = byte => {
  let rtn = 0;
  if(byte >= lowerA) {
    rtn = byte - lowerA + 10;
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
    return String.fromCharCode(num + lowerA - 26);
  } else {
    return String.fromCharCode(num + upperA);
  }
};

const readline = require('readline');
const fs = require('fs');

function main() {
  // challenge 1
  const input = hexStringToBuffer('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');
  console.log('Challenge 1');
  console.log('Expected:', 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
  console.log('Actual  :', hexToBase64(input).toString());

  // challenge 2
  const a = hexStringToBuffer('1c0111001f010100061a024b53535009181c');
  const b = hexStringToBuffer('686974207468652062756c6c277320657965');
  const result = fixedXor(a, b);
  console.log('Challenge 2');
  console.log('Expected:', '746865206b696420646f6e277420706c6179');
  console.log('Actual  :', bufferToHexString(result));

  // challenge 3
  const encrypted = hexStringToBuffer('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
  const decrypted = decryptXor(encrypted).buffer;
  console.log('Challenge 3');
  console.log('Input   :', bufferToHexString(encrypted));
  console.log('Output  :', decrypted.toString());

  // challenge 4
  const fileStream = fs.createReadStream('4.txt');
  const lineReader = readline.createInterface({
    input: fileStream
  });

  const lines = [];
  lineReader.on('line', (line) => {
    const buffer = hexStringToBuffer(line);
    lines.push(decryptXor(buffer));
  });

  lineReader.on('close', () => {
    const decrypted = lines
      .reduce((acc, obj) => {
        if(obj.error <= acc.error) {
          return obj;
        }
        return acc;
      }, { error: Infinity, buffer: new Buffer(lines[0].buffer.length).fill(0) })
      .buffer;
    console.log('Challenge 4');
    console.log('Input   :', 'file<4.txt>');
    console.log('Output  :', decrypted.toString());
  });

  // challenge 5
  const inputString = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  console.log('Challenge 5');
  console.log('Expected:', '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f');
  console.log('Actual  :', bufferToHexString(encryptRepeatingKeyXor('ICE', inputString)));
}
main();
