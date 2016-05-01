import unittest
import set2
import base64

class TestSet2(unittest.TestCase):
    def test_pkcs7padding(self):
        self.assertEqual(set2.pkcs7padding(b'YELLOW SUBMARINE', 20), b'YELLOW SUBMARINE\x04\x04\x04\x04')

    def test_cbc_mode(self):
        text = b'HELLO WORLD     '
        key = b'YELLOW SUBMARINE'
        iv = bytes([0] * len(key))

        encrypted = set2.aes_cbc_mode_encrypt(text, key, iv)
        decrypted = set2.aes_cbc_mode_decrypt(encrypted, key, iv)

        self.assertEqual(text, decrypted)

    def test_cbc_decrypt(self):
        with open('10.txt') as f:
            contents = bytes(base64.b64decode(f.read()))
            key = b'YELLOW SUBMARINE'
            iv = bytes([0] * len(key))
            self.assertIn(b"I'm back and I'm ringin' the bell \nA rockin'", set2.aes_cbc_mode_decrypt(contents, key, iv))

    def test_detection_oracle(self):
        mode, result = set2.encryption_oracle(b'HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     ')
        self.assertEqual(mode, set2.detection_oracle(result))

    def test_byte_ecb_decryption(self):
        randomly_encrypted = set2.encrypt_unknown_string_ecb(b'HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     ')
        result = set2.byte_ecb_decryption(randomly_encrypted)
        self.assertEqual(result, b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")

if __name__ == '__main__':
    unittest.main()
