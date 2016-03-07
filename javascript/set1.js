'use strict';
const utils = require('./utils');

// challenge 1 function
function hexToBase64(hexBuffer) {
  const str = hexBuffer.reduce((acc, current) => acc + utils.padBinary(current.toString(2)), '');
  const result = new Buffer(str.length / 6);
  result.fill(0);
  for(let i = 0; i < str.length / 6; i++) {
    const strIndex = i * 6;
    result[i] = parseInt(str.slice(strIndex, strIndex+6), 2);
  }

  return Array.prototype.map.call(result, utils.numToBase64).join('');
}

// challenge 2 function
function fixedXor(a, b) {
  return new Buffer(Array.prototype.map.call(a, (n,i) => n ^ b[i]));
}

// challenge 3
function decryptXor(buffer) {

  /*let bytes = [];
  for(let i = 0; i < 255; i++) {
    bytes.push(i);
  }
  */
 let bytes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*() :'.split('')

  return bytes
    .map(character => {
      const characterBuffer = new Buffer(buffer.length);
      characterBuffer.fill(character);

      const xored = fixedXor(buffer, characterBuffer);
      const string = xored.toString();
      return { buffer: xored, error: utils.stringError(string), character };
    })
    .reduce((acc, obj) => {
      if(obj.error <= acc.error) {
        return obj;
      }
      return acc;
    }, { error: Infinity, buffer: new Buffer(buffer.length).fill(0), character: null });
}

// challenge 4
function detectFixedXor (filename) {
  return utils.readLines(filename)
    .then(lines => lines.map(line => decryptXor(utils.hexStringToBuffer(line))))
    .then(lines => {
      return lines
        .reduce((acc, obj) => {
          if(obj.error <= acc.error) {
            return obj;
          }
          return acc;
        }, { error: Infinity, buffer: new Buffer(lines[0].buffer.length).fill(0) })
        .buffer;
    });
}

// challenge 5
function encryptRepeatingKeyXor (key, buffer) {
  if(!Buffer.isBuffer(buffer)) {
    buffer = utils.stringToBuffer(buffer);
  }

  const repeatingKeyBuffer = utils.stringToBuffer(key.repeat(Math.ceil(buffer.length / key.length)));

  return fixedXor(buffer, repeatingKeyBuffer);
}

function breakRepeatingKeyXor (filename) {
  const p = utils.readFile(filename)
    .then(buffer => new Buffer(buffer.toString().replace(/\n/g, '')))
    .then(utils.base64ToBuffer)
    .then(buffer => {
      const keySizes = [];
      for(let keySize = 2; keySize < 40; keySize++) {
        const first = buffer.slice(0, keySize), second = buffer.slice(keySize, keySize * 2);

        const dist = utils.hammingDistance(first, second) / keySize;

        keySizes.push({ dist, keySize });
      }
      keySizes.sort(function(a, b) {
        if(a.dist < b.dist) {
          return -1;
        } else if(b.dist < a.dist) {
          return 1;
        } else {
          return 0;
        }
      });

      const keys = keySizes
        .map(obj => obj.keySize)
        .map(keySize => utils.breakIntoBlocks(buffer, keySize))
        .map(utils.transpose)
        .map(blocks => blocks.map(decryptXor).map(obj => obj.character).join(''));

      const result = keys.map(key => encryptRepeatingKeyXor.bind(null, key))
        .map(f => f(buffer))
        .map(buffer => ({ buffer, error: utils.stringError(buffer.toString()) }))
        .reduce((acc, obj) => {
          if(obj.error <= acc.error) {
            return obj;
          }
          return acc;
        }, { error: Infinity, buffer: new Buffer(buffer.length).fill(0) })
        .buffer;

      return result;
    });

  return p;
}

module.exports = {
  hexToBase64,
  fixedXor,
  decryptXor,
  detectFixedXor,
  encryptRepeatingKeyXor,
  breakRepeatingKeyXor
};
