package main

import (
  "fmt"
  "mycrypto"
)

func main() {
  // challenge 1
  fmt.Println("Challenge 1")
  fmt.Println("Expecting:","SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
  bytes := mycrypto.HexToBytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
  base64Bytes := mycrypto.HexToBase64(bytes)
  fmt.Println("Actual:   ",mycrypto.Base64BytesToString(base64Bytes))
  fmt.Println()

  // challenge 2
  fmt.Println("Challenge 2")
  fmt.Println("Expecting:","746865206b696420646f6e277420706c6179")
  a := mycrypto.HexToBytes("1c0111001f010100061a024b53535009181c")
  b := mycrypto.HexToBytes("686974207468652062756c6c277320657965")
  c := mycrypto.XOR(a, b)
  fmt.Println("Actual:   ", mycrypto.HexBytesToString(c))
  fmt.Println()

  // challenge 3
  fmt.Println("Challenge 3")
  fmt.Println("Encrypted String:", "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  encrypted := mycrypto.HexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  result := mycrypto.XORDecrypt(encrypted)
  fmt.Println("Decrypted Result:", string(result))
  fmt.Println()

  // challenge 4

}
