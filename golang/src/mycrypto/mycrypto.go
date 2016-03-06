package mycrypto

import (
  "fmt"
  "math"
  "strings"
  "encoding/hex"
)

// TOOD error checking
func HexToBase64(hexbytes []byte) (base64Bytes []byte) {

  var fullstring string = ""

  // convert the bytes into one very long string
  for i := 0; i < len(hexbytes); i++ {
    fullstring = fullstring + fmt.Sprintf("%08b", hexbytes[i])
  }

  // every six characters make a new byte
  var index int
  for base := 0; base < len(fullstring) / 6; base++ {
    index = base * 6

    // convert the six characters into their bit representation
    bits := fullstring[index:index+6]
    var bitsSum byte
    for i := 0; i < len(bits); i++ {
      bitsSum = bitsSum + (1 << byte(len(bits) - i - 1)) * byte(bits[i] - '0')
    }

    // add it to the result string
    base64Bytes = append(base64Bytes, bitsSum)
  }

  return
}

// TODO error checking
func XOR(a, b []byte) (result []byte) {
  for i := 0; i < len(a); i++ {
    result = append(result, a[i] ^ b[i])
  }

  return
}

func englishScore(str string) (error float64) {

  // taken from wikipedia
  // https://en.wikipedia.org/wiki/Letter_frequency
  englishFreq := map[byte]float64 {
    'e': 0.12702,
    't': 0.09056,
    'a': 0.08167,
    'o': 0.07507,
    'i': 0.06966,
    'n': 0.06749,
    's': 0.06327,
    'h': 0.06094,
    'r': 0.05987,
    'd': 0.04253,
    'l': 0.04025,
    'c': 0.02782,
    'u': 0.02758,
    'm': 0.02406,
    'w': 0.02361,
    'f': 0.02228,
    'g': 0.02015,
    'y': 0.01974,
    'p': 0.01929,
    'b': 0.01492,
    'v': 0.00978,
    'k': 0.00772,
    'j': 0.00153,
    'x': 0.00150,
    'q': 0.00095,
    'z': 0.00074,
  }

  total := float64(0)
  strFreq := map[byte]float64 {
    'e': 0,
    't': 0,
    'a': 0,
    'o': 0,
    'i': 0,
    'n': 0,
    's': 0,
    'h': 0,
    'r': 0,
    'd': 0,
    'l': 0,
    'c': 0,
    'u': 0,
    'm': 0,
    'w': 0,
    'f': 0,
    'g': 0,
    'y': 0,
    'p': 0,
    'b': 0,
    'v': 0,
    'k': 0,
    'j': 0,
    'x': 0,
    'q': 0,
    'z': 0,
  }

  lower := strings.ToLower(str)
  for i := 0; i < len(lower); i++ {
    _, ok := strFreq[lower[i]]
    if ok {
      strFreq[lower[i]] = strFreq[lower[i]] + 1
      total = total + 1
    }
  }

  for k := range englishFreq {
    error = error + math.Abs(englishFreq[k] - strFreq[k] / total)
  }

  return
}

func XORDecrypt(encrypted []byte) (result []byte) {

  // from A-Z
  minError := math.Inf(1)
  for i := 65; i <= 90; i++ {
    // make the key
    key := make([]byte, len(encrypted));
    for j := 0; j < len(encrypted); j++ {
      key[j] = byte(i)
    }

    // decrypt the bytes
    decryptedBytes := XOR(encrypted, key)
    decrypted := string(decryptedBytes)
    err := englishScore(decrypted)
    if err < minError {
      minError = err
      result = decryptedBytes
    }
  }

  return
}

/*
UTIL FUNCTIONS
 */

func HexToBytes(input string) (hexbytes []byte) {
  hexbytes,_ = hex.DecodeString(input)
  return
}

func HexBytesToString(input []byte) (result string) {
  result = hex.EncodeToString(input)
  return
}

func Base64BytesToString(input []byte) (result string) {

  result = ""
  for i := 0; i < len(input); i++ {
    if input[i] <= 25 {
      result = result + string(input[i] + 'A')
    } else if input[i] <= 51 {
      result = result + string((input[i] - 26) + 'a')
    } else if input[i] <= 61 {
      result = result + string((input[i] - 52) + '0')
    } else if input[i] == 62 {
      result = result + "+"
    } else {
      result = result + "/"
    }
  }

  // pad == at the end
  // numPadChars := 3 - int(math.Mod(float64(len(input)), 3))
  // for i := 0; i < numPadChars; i++ {
    // result = result + "="
  // }

  return
}
