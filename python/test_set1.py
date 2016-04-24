import unittest
import set1
import base64

class TestSet1(unittest.TestCase):

    def test_base_64_to_hex(self):
        self.assertEqual(set1.hex_to_base64(bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")), b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    def test_fixed_xor(self):
        self.assertEqual(set1.fixed_xor(bytes.fromhex("1c0111001f010100061a024b53535009181c"), bytes.fromhex("686974207468652062756c6c277320657965")), bytes.fromhex("746865206b696420646f6e277420706c6179"))

    def test_decipher_singlebyte(self):
        deciphered,error,char = set1.decipher_singlebyte_xor(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
        self.assertEqual(deciphered, b"Cooking MC's like a pound of bacon")

    def test_detect_singlebyte(self):
        with open('4.txt') as f:
            deciphered,error,char = set1.detect_singlebyte_xor(f.readlines())
            self.assertEqual(deciphered, b'Now that the party is jumping\n')

    def test_repeating_key_xor(self):
        text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        out = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

        self.assertEqual(set1.repeating_key_xor(text, b'ICE'), out)

    def test_hamming_distance(self):
        a = b'this is a test'
        b = b'wokka wokka!!!'

        self.assertEqual(set1.hamming_distance(a,b), 37)

    def test_break_repeating_key_xor(self):
        with open('6.txt') as f:
            contents = bytes(base64.b64decode(f.read()))
            deciphered, key, error = set1.break_repeating_key_xor(contents)

            self.assertIn(b"I'm back and I'm ringin' the bell \nA rockin'", deciphered)

    def test_aes_ecb_mode(self):
        with open('7.txt') as f:
            contents = bytes(base64.b64decode(f.read()))
            deciphered = set1.decrypt_aes_ecb(contents, 'YELLOW SUBMARINE')

            self.assertIn(b"I'm back and I'm ringin' the bell \nA rockin'", deciphered)

    def test_detect_aes_ecb_mode(self):
        with open('8.txt') as f:
            lines = f.readlines()
            deciphered = set1.detect_aes_ecb(lines)
            self.assertEqual(deciphered, [133])

if __name__ == '__main__':
    unittest.main()
