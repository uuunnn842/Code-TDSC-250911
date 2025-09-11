package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

var (
	Byt = int(32)
)

// ---------- Chebyshev chaotic-map ----------
var memo = make(map[string]*big.Int)

func T(n, x, mod *big.Int) *big.Int {
	key := n.String() + "," + x.String()
	if val, ok := memo[key]; ok {
		return new(big.Int).Set(val)
	}
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	result := new(big.Int)

	switch n.Cmp(zero) {
	case 0:
		result.Set(one)
	case 1:
		if n.Cmp(one) == 0 {
			result.Mod(x, mod)
		} else {
			rem := new(big.Int).Mod(n, two)
			if rem.Cmp(zero) == 0 { // even
				half := new(big.Int).Rsh(n, 1)
				temp := T(half, x, mod)
				sqr := new(big.Int).Mul(temp, temp)
				result.Sub(new(big.Int).Mul(two, sqr), one)
				result.Mod(result, mod)
			} else { // odd
				nSub1 := new(big.Int).Sub(n, one)
				nAdd1 := new(big.Int).Add(n, one)
				h1 := new(big.Int).Rsh(nSub1, 1)
				h2 := new(big.Int).Rsh(nAdd1, 1)
				t1 := T(h1, x, mod)
				t2 := T(h2, x, mod)
				prod := new(big.Int).Mul(t1, t2)
				result.Sub(new(big.Int).Mul(two, prod), x)
				result.Mod(result, mod)
			}
		}
	}
	memo[key] = new(big.Int).Set(result)
	return result
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randBits(bit int) *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), uint(bit))
	min := new(big.Int).Lsh(big.NewInt(1), uint(bit-1))
	r, _ := rand.Int(rand.Reader, new(big.Int).Sub(max, min))
	return r.Add(r, min)
}

// ---------- MSM (P-256) ----------
func msmP256(scalars []*big.Int, pointsX, pointsY []*big.Int) (rx, ry *big.Int) {
	curve := elliptic.P256()
	rx, ry = big.NewInt(0), big.NewInt(0)
	for i := range scalars {
		px, py := curve.ScalarMult(pointsX[i], pointsY[i], scalars[i].Bytes())
		rx, ry = curve.Add(rx, ry, px, py)
	}
	return
}

func benchMSM32() time.Duration {
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	n := 32
	scalars := make([]*big.Int, n)
	pointsX := make([]*big.Int, n)
	pointsY := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, curve.Params().N)
		scalars[i] = k
		pointsX[i] = Gx
		pointsY[i] = Gy
	}
	start := time.Now()
	_, _ = msmP256(scalars, pointsX, pointsY)
	return time.Since(start)
}

// ---------- FFDHE2048 ----------
var ffdhe2048p = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xAD, 0xF8, 0x54, 0x58, 0xC2, 0x50, 0x4D, 0xD9,
	0x97, 0x7C, 0x02, 0x18, 0x4C, 0x23, 0x36, 0xE5,
	0x05, 0x94, 0x99, 0xB1, 0xF9, 0x56, 0x7C, 0xA9,
	0x58, 0xD3, 0x0D, 0x39, 0xED, 0x5F, 0xBE, 0x11,
	0x29, 0x07, 0x61, 0xC5, 0x4C, 0x11, 0xA7, 0x18,
	0x47, 0x18, 0x2E, 0x09, 0x31, 0x66, 0x78, 0x2E,
	0x38, 0x8C, 0x35, 0x1D, 0x52, 0xC0, 0xB0, 0x25,
	0x53, 0x6D, 0x11, 0x2C, 0xE0, 0xC7, 0x3C, 0x98,
	0x5B, 0x5C, 0xA9, 0xAB, 0x1B, 0x71, 0xC3, 0x5B,
	0x5A, 0x3D, 0x72, 0x6E, 0x42, 0x14, 0x05, 0xC5,
	0xEA, 0x12, 0x4D, 0xFA, 0x3F, 0x7D, 0x3F, 0x79,
	0xD9, 0x11, 0x84, 0xC7, 0x39, 0x5A, 0x2C, 0x79,
	0x05, 0x12, 0x07, 0x8B, 0x37, 0x59, 0x55, 0x95,
	0x5F, 0x51, 0x0C, 0xC6, 0x11, 0xAF, 0x43, 0x91,
	0x61, 0x0C, 0x87, 0xB3, 0x58, 0x7F, 0xD8, 0x41,
	0xA5, 0xD6, 0x73, 0xC9, 0x1D, 0x94, 0x3F, 0x17,
	0x6E, 0x24, 0x8C, 0x8F, 0xB1, 0x2A, 0x8A, 0x8B,
	0x8C, 0xF4, 0x0C, 0x31, 0x90, 0x8C, 0x60, 0x06,
	0xCF, 0x9F, 0x3C, 0x3B, 0xA3, 0x16, 0x63, 0x78,
	0x5D, 0x30, 0x5B, 0x51, 0x21, 0x59, 0xBB, 0x39,
	0x9B, 0x2E, 0x2A, 0xA3, 0x2E, 0x5C, 0x4B, 0xD8,
	0x1A, 0xFA, 0xD0, 0x5A, 0xDD, 0xC9, 0x9D, 0x2B,
	0x86, 0xED, 0x3C, 0x9A, 0x8B, 0x90, 0x5B, 0xC9,
	0x59, 0x7F, 0x59, 0x85, 0x52, 0x84, 0xAF, 0x1F,
})

func benchModExp() time.Duration {
	g := big.NewInt(2)
	a, _ := rand.Int(rand.Reader, new(big.Int).Sub(ffdhe2048p, big.NewInt(1)))
	a.Add(a, big.NewInt(1))
	start := time.Now()
	_ = new(big.Int).Exp(g, a, ffdhe2048p)
	return time.Since(start)
}

// ---------- 4. SHA-256 ----------

func benchmark(name string, echo int, fn func()) {
	t0 := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		fn()
	}
	t1 := time.Now().UnixNano()
	elapsed := t1 - t0
	fmt.Printf("%s Total time: %.3f ms | Average per call: %.3f us \n", name, float64(elapsed)/1e6, float64(elapsed)*1e3/1e6/float64(echo))
}
func Hash(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}
func RS(Byt int) []byte {
	r := make([]byte, Byt)
	rand.Read(r)
	return r
}
func concat(bb ...[]byte) []byte {
	var n int
	for _, b := range bb {
		n += len(b)
	}
	out := make([]byte, n)

	var off int
	for _, b := range bb {
		off += copy(out[off:], b)
	}
	return out
}
func Xor(parts ...[]byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	minLen := len(parts[0])
	for _, p := range parts[1:] {
		if len(p) < minLen {
			minLen = len(p)
		}
	}
	dst := make([]byte, minLen)

	for i := 0; i < minLen; i++ {
		val := parts[0][i]
		for _, p := range parts[1:] {
			val ^= p[i]
		}
		dst[i] = val
	}
	return dst
}

// AES CTR
func AESEncryptCTR(PlainText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("err")
	}
	iv := []byte("12345678asdfghjk")
	stream := cipher.NewCTR(block, iv)
	cipherText := make([]byte, len(PlainText))
	stream.XORKeyStream(cipherText, PlainText)
	return cipherText
}
func AESDecryptCTR(cipherText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("err")
	}
	iv := []byte("12345678asdfghjk")
	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(cipherText, cipherText)
	return cipherText
}
func Runtime(echo int) {
	d0 := RS(Byt)
	d1 := RS(Byt)
	d2 := RS(Byt)
	d3 := RS(Byt)
	d4 := RS(Byt)

	// println(len(Hash(d0)))
	// println(len(concat(d0, d1, d2, d3, d4)))

	println("/*------------timestamp----------*/")
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		T1 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T1, uint64(time.Now().UnixNano()))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println("8 bytes timestamp", oot/1e6, "ms ", Ot-ot, "ns")

	println("/*------------random number----------*/")
	benchmark("32 bytes random number", echo,
		func() { RS(Byt) })

	println("/*------------concat----------*/")
	benchmark("5-1 Data (32 bytes) Connection concat", echo,
		func() { concat(d0, d1, d2, d3, d4) })

	println("/*------------SHA256----------*/")
	data5 := concat(d0, d1, d2, d3, d4)
	benchmark("5 Data (32 bytes) Hash-concat", echo,
		func() { Hash(data5) })

	println("/*------------Xor----------*/")
	benchmark("5 Data (32 bytes) Xor", echo,
		func() { Xor(d0, d1, d2, d3, d4) })

	println("/*------------AES-CTR----------*/")
	k := RS(Byt)
	in := RS(Byt * 2)
	EM := AESEncryptCTR(in, k)

	ot = time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		AESEncryptCTR(in, k)
	}
	Ot = time.Now().UnixNano()
	oot = float64(Ot - ot)
	fmt.Println("2 Data (32 bytes) AES-EN", oot/1e6, "ms ", Ot-ot, "ns")

	ot = time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		AESDecryptCTR(EM, k)
	}
	Ot = time.Now().UnixNano()
	oot = float64(Ot - ot)
	fmt.Println("2 Data (32 bytes) AES-DE", oot/1e6, "ms ", Ot-ot, "ns")
}
func main() {
	const echo = 10000

	fmt.Println("=== Chebyshev chaotic-map 256-bit ===")
	totalT := time.Duration(0)
	for i := 0; i < echo; i++ {
		for k := range memo {
			delete(memo, k)
		}
		n := randBits(256)
		x := randBits(256)
		mod := new(big.Int).Lsh(big.NewInt(1), 256)
		start := time.Now()
		T(n, x, mod)
		totalT += time.Since(start)
	}
	fmt.Printf("Total time: %v | Average per call: %v\n", totalT, totalT/echo)

	fmt.Println("\n=== MSM P-256 ===")
	totalMSM := time.Duration(0)
	for i := 0; i < echo; i++ {
		totalMSM += benchMSM32()
	}
	fmt.Printf("Total time: %v | Average per call: %v\n", totalMSM, totalMSM/echo)

	fmt.Println("\n=== g^a mod p (FFDHE2048) ===")
	totalMod := time.Duration(0)
	for i := 0; i < echo; i++ {
		totalMod += benchModExp()
	}
	fmt.Printf("Total time: %v | Average per call: %v\n", totalMod, totalMod/echo)

	Runtime(echo)

}
