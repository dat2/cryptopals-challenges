const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const expect = chai.expect;

const utils = require('../utils');
const set1 = require('../set1');

describe('set1', function (){
  describe('challenge1', function () {
    it('should pass the test case given', function () {
      const input = utils.hexStringToBuffer('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');
      expect(set1.hexToBase64(input).toString()).to.equal('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');
    });
  });

  describe('challenge2', function() {
    it('should pass the test case given', function() {
      const a = utils.hexStringToBuffer('1c0111001f010100061a024b53535009181c');
      const b = utils.hexStringToBuffer('686974207468652062756c6c277320657965');
      const result = utils.bufferToHexString(set1.fixedXor(a, b));

      expect(result).to.be.equal('746865206b696420646f6e277420706c6179');
    })
  });

  describe('challenge3', function() {
    it('should pass the test case given', function() {
      const encrypted = utils.hexStringToBuffer('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
      const decrypted = set1.decryptXor(encrypted).buffer;
      expect(decrypted.toString()).to.be.equal('Cooking MC\'s like a pound of bacon');
    });
  });

  describe('challenge4', function() {
    it('should pass the test case given', function() {
      const p = set1.detectFixedXor('4.txt').then(b => b.toString());
      return expect(p).to.eventually.equal('Now that the party is jumping\n');
    });
  });

  describe('challenge5', function() {
    it('should pass the test case given', function() {
      const inputString = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
      const encrypted = set1.encryptRepeatingKeyXor('ICE', inputString);
      const expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';
      expect(utils.bufferToHexString(encrypted)).to.be.equal(expected);
    });
  });

  describe('challenge6', function() {
    it('should calculate hamming distance correctly', function() {
      const a = new Buffer('this is a test');
      const b = new Buffer('wokka wokka!!!');

      expect(utils.hammingDistance(a, b)).to.be.equal(37);
    });

    it('should convert base64 strings to a buffer', function() {
      const a = new Buffer('TWFu');
      const result = new Buffer('Man');
      expect(utils.base64ToBuffer(a)).to.deep.equal(result);

      const b = new Buffer('YW55IGNhcm5hbCBwbGVhc3VyZS4=');
      const result2 = new Buffer('any carnal pleasure.');
      expect(utils.base64ToBuffer(b)).to.deep.equal(result2);

      const c = new Buffer('YW55IGNhcm5hbCBwbGVhc3VyZQ==');
      const result3 = new Buffer('any carnal pleasure');
      expect(utils.base64ToBuffer(c)).to.deep.equal(result3);
    });

    it('should transpose buffers correctly', function() {
      const bufs = [new Buffer([1,2,3]), new Buffer([4,5,6]), new Buffer([7,8,9])];
      const transpose = [new Buffer([1,4,7]), new Buffer([2,5,8]), new Buffer([3,6,9])];

      expect(Buffer.concat(utils.transpose(bufs), 9)).to.deep.equal(Buffer.concat(transpose, 9));
    });

    it('should break repeating-key xor', function() {
      this.timeout(15000);
      // return expect(set1.breakRepeatingKeyXor('6.txt').then(b => b.toString())).to.eventually.contain("I\'m back and I\'m ringin\' the bell");
    });
  });

  describe('challenge7', function() {
    it('should decrypt the file', function() {
      this.timeout(15000);
      return expect(set1.decryptAesEcb('7.txt').then(b => b.toString())).to.eventually.equal(null);
    });
  })
});
