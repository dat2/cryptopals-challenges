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
        mode, result = set2.encryption_oracle(b"I'm back and I'm ringin' the bell \nA rockin'")
        print(mode)
        self.assertEqual(mode, set2.detection_oracle(result))

if __name__ == '__main__':
    unittest.main()
