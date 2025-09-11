package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"unsafe"

	// mathrand "math/rand"
	"fmt"
	"time"
)

var (
	Byt = int(32)
)

func main() {
	echo := int(1e5)

	DXie(echo)
	ASXie(echo)
	CSXie(echo)
	println()
	DOur(echo)
	ASOur(echo)
	CSOur(echo)

}
func DXie(echo int) {
	fmt.Print("Xie D echo:", echo, "; time:")
	HID := RS(Byt)
	PW := RS(Byt)
	R := RS(Byt)
	Vi := RS(Byt)
	Yi := RS(Byt)
	ASj := RS(Byt)
	Bij := RS(Byt)
	M6 := RS(Byt)
	IDCS := RS(Byt)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step1
		x1 := RS(Byt)
		x2 := RS(Byt)
		ARG1 := Xor(Vi, Hash(concat(HID, PW, R)))
		ARG2 := Hash(concat(ASj, ARG1))
		Xi := Xor(Yi, PW, HID)
		Aij := Xor(Bij, Xi)
		Xor(HID, x1, ARG2)             //SHID
		Xor(ARG2, x1)                  //M1
		Xor(Hash(concat(Aij, x1)), x2) //M2
		M3 := Hash(concat(HID, x1, x2))
		T1 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T1, uint64(time.Now().UnixNano()))
		Hash(concat(HID, ASj, M3, T1)) //AUTE

		//Step4
		T3 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T3, uint64(time.Now().UnixNano()))
		M4 := Hash(concat(HID, ASj, x1, x2, Aij))
		y := Xor(M6, M4)
		SK := Hash(concat(M4, ASj, IDCS, y, T3))
		Hash(concat(SK, M4, y)) //check AUs
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}
func ASXie(echo int) {
	fmt.Print("Xie AS echo:", echo, "; time:")
	ASj := RS(Byt)
	SV1 := RS(Byt)
	M1 := RS(Byt)
	M2 := RS(Byt)
	SHID := RS(Byt)
	SV2 := RS(Byt)
	SKjk := RS(Byt)
	// hash := md5.New()

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step 2
		T1 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T1, uint64(time.Now().UnixNano()))
		ARG2 := Hash(concat(ASj, SV1))
		x1 := Xor(M1, ARG2)
		HID := Xor(SHID, x1, ARG2)
		Aij := Hash(concat(HID, SV2))
		x2 := Xor(Hash(concat(Aij, x1)), M2)
		M3 := Hash(concat(HID, x1, x2))

		Hash(concat(HID, ASj, M3, T1)) //AUTE
		M4 := Hash(concat(HID, ASj, x1, x2, Aij))
		T2 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T2, uint64(time.Now().UnixNano()))
		AESEncryptCTR(concat(M4, T2), SKjk) //M5
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func CSXie(echo int) {
	fmt.Print("Xie CS echo:", echo, "; time:")
	ASj := RS(Byt)
	IDCS := RS(Byt)
	SKjk := RS(Byt)
	T2 := make([]byte, 8) //timestamp
	binary.BigEndian.PutUint64(T2, uint64(time.Now().UnixNano()))
	M5 := AESEncryptCTR(concat(Hash(RS(Byt)), T2), SKjk) //M5
	// hash := md5.New()

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step 3
		M4 := AESDecryptCTR(M5, SKjk)[:Byt]
		// fmt.Println(len(M4))
		T2 = make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T2, uint64(time.Now().UnixNano()))

		y := RS(Byt)
		Xor(y, M4)            //M6
		T3 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T3, uint64(time.Now().UnixNano()))
		SKik := Hash(concat(M4, ASj, IDCS, y, T3))
		Hash(concat(SKik, M4, y)) //AUS
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func DOur(echo int) {
	fmt.Print("Our D echo:", echo, "; time:")
	EID := RS(Byt)
	ID := RS(Byt)
	PW := RS(Byt)
	ri := RS(Byt)
	Vi := RS(Byt)
	EAij := RS(Byt)
	ASj := RS(Byt)
	Er2 := RS(Byt)
	ctrij := 0
	ekij := RS(Byt)
	// Auji := AESEncryptCTR(RS(3*Byt), key)
	// hash := md5.New()

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step1
		Hash(concat(ID, PW)) //LA
		r1 := RS(Byt)
		TV1 := Xor(Vi, Hash(concat(ID, PW, ri)))
		TV2 := Hash(concat(ASj, TV1))
		Aij := Xor(EAij, Hash(concat(ri, ID, PW)))
		ctrij++
		ekij = Hash(ekij)
		Xor(TV2, r1)                    //Er1
		Xor(EID, Hash(concat(r1, TV2))) //EEID
		ctr := make([]byte, 8)
		binary.BigEndian.PutUint64(ctr, uint64(ctrij))
		Xor(ctr, Hash(concat(r1, TV2, Aij))[:8]) //Ectrij

		T1 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T1, uint64(time.Now().UnixNano()))
		Hash(concat(EID, r1, ctr, T1)) //AUTEij

		//Step4
		T3 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T3, uint64(time.Now().UnixNano()))
		TV3 := Hash(concat(EID, r1, ekij, Aij, ASj))
		r2 := Xor(Er2, TV3)
		SK := Hash(concat(TV3, r2, T3))
		Hash(concat(r2, TV3, SK, T3)) //check Authki
		ctrij++
		ekij = Hash(ekij)
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}
func ASOur(echo int) {
	fmt.Print("Our AS echo:", echo, "; time:")
	ASj := RS(Byt)
	SV1 := RS(Byt)
	Er1 := RS(Byt)
	EEID := RS(Byt)
	Ectrij := RS(8)
	SV2 := RS(Byt)
	ekij := RS(Byt)
	ctrij := 0
	akjk := RS(Byt)
	ekjk := RS(Byt)
	ctrjk := 0
	// hash := md5.New()

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step 2
		T1 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T1, uint64(time.Now().UnixNano()))
		TV2 := Hash(concat(ASj, SV1))
		r1 := Xor(Er1, TV2)
		EID := Xor(EEID, Hash(concat(r1, TV2)))
		Aij := Hash(concat(EID, SV2))
		ctr := Xor(Ectrij, Hash(concat(r1, TV2, Aij))[:8]) //get ctrij'
		ctrij++
		ekij = Hash(ekij)
		TV3 := Hash(concat(EID, r1, ekij, Aij, ASj))
		ETV3 := Xor(TV3, Hash(concat(ekij, ctr))) //ETV3
		T2 := make([]byte, 8)                     //timestamp
		binary.BigEndian.PutUint64(T2, uint64(time.Now().UnixNano()))
		Hash(concat(akjk, ctr, ETV3, T2)) //Authjk
		ctrij++
		ekij = Hash(ekij)
		ctrjk++
		ekjk = Hash(ekjk)
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func CSOur(echo int) {
	fmt.Print("Our CS echo:", echo, "; time:")
	akjk := RS(Byt)
	ekjk := RS(Byt)
	ctrjk := 0
	ctr := RS(8)
	ETV3 := RS(Byt)
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//Step 3
		T2 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T2, uint64(time.Now().UnixNano()))

		Hash(concat(akjk, ctr, ETV3, T2)) //Authjk
		r2 := RS(Byt)
		TV3 := Xor(ETV3, Hash(concat(ekjk, ctr)))
		Xor(r2, TV3)          //Er2
		T3 := make([]byte, 8) //timestamp
		binary.BigEndian.PutUint64(T3, uint64(time.Now().UnixNano()))

		SK := Hash(concat(TV3, r2, T3))
		Hash(concat(r2, TV3, SK, T3)) //Authki
		ctrjk++
		ekjk = Hash(ekjk)

	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

/**------------*/
func benchmark(name string, echo int, fn func()) {
	t0 := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		fn()
	}
	t1 := time.Now().UnixNano()
	elapsed := t1 - t0
	fmt.Printf("%s echo:%d %.3f ms %d ns\n", name, echo, float64(elapsed)/1e6, elapsed)
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

func XorUnsafe(parts ...[]byte) []byte {
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

	n64 := minLen / 8
	if n64 > 0 {
		d64 := (*[]uint64)(unsafe.Pointer(&dst))
		p64 := make([][]uint64, len(parts))
		for j := range parts {
			p64[j] = *(*[]uint64)(unsafe.Pointer(&parts[j]))
		}
		for i := 0; i < n64; i++ {
			v := p64[0][i]
			for j := 1; j < len(p64); j++ {
				v ^= p64[j][i]
			}
			(*d64)[i] = v
		}
	}

	off := n64 * 8
	for i := off; i < minLen; i++ {
		val := parts[0][i]
		for _, p := range parts[1:] {
			val ^= p[i]
		}
		dst[i] = val
	}
	return dst
}

func getAnd(a []byte, b []byte) []byte {
	la := len(a)
	lb := len(b)
	c := make([]byte, la+lb)
	for i := 0; i < la; i++ {
		c[i] = a[i]
	}
	for i := la; i < la+lb; i++ {
		c[i] = b[i-la]
	}
	return c
}
func getAnd3(a []byte, b []byte, c []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	cc := make([]byte, la+lb+lc)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	return cc
}
func getAnd4(a []byte, b []byte, c []byte, d []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	cc := make([]byte, la+lb+lc+ld)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	for ; i < la+lb+lc+ld; i++ {
		cc[i] = c[i-la-lb-lc]
	}
	return cc
}
func getAnd5(a []byte, b []byte, c []byte, d []byte, e []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	le := len(e)
	cc := make([]byte, la+lb+lc+ld+le)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	for ; i < la+lb+lc+ld; i++ {
		cc[i] = c[i-la-lb-lc]
	}
	for ; i < la+lb+lc+ld+le; i++ {
		cc[i] = c[i-la-lb-lc-ld]
	}
	return cc
}
func getOxr(a []byte, b []byte) []byte {
	la := len(a)
	lb := len(b)
	if la > lb {
		c := make([]byte, la)
		i := 0
		t := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			c[i] = a[i] ^ b[t]
			t++
		}
		return c
	}
	c := make([]byte, lb)
	i := 0
	t := 0
	for ; i < lb; i++ {
		if i%la == 0 {
			t = 0
		}
		c[i] = b[i] ^ a[t]
		t++
	}
	return c
}
func getOxr3(a []byte, b []byte, c []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	if la >= lb && la >= lc {
		cc := make([]byte, la)
		i := 0
		t := 0
		tt := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			cc[i] = a[i] ^ b[t] ^ c[tt]
			t++
			tt++
		}
		return cc
	}
	if lb >= la && lb >= lc {
		cc := make([]byte, lb)
		i := 0
		t := 0
		tt := 0
		for ; i < lb; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			cc[i] = b[i] ^ a[t] ^ c[tt]
			t++
			tt++
		}
		return cc
	}
	cc := make([]byte, lc)
	i := 0
	t := 0
	tt := 0
	for ; i < lc; i++ {
		if i%la == 0 {
			t = 0
		}
		if i%lb == 0 {
			tt = 0
		}
		cc[i] = c[i] ^ a[t] ^ b[tt]
		t++
		tt++
	}
	return cc
}
func getOxr4(a []byte, b []byte, c []byte, d []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	if la >= lb && la >= lc && la >= ld {
		cc := make([]byte, la)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%ld == 0 {
				ttt = 0
			}
			cc[i] = a[i] ^ b[t] ^ c[tt] ^ d[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	if lb >= la && lb >= lc && lb >= ld {
		cc := make([]byte, lb)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < lb; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%ld == 0 {
				ttt = 0
			}
			cc[i] = b[i] ^ a[t] ^ c[tt] ^ d[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	if ld >= la && ld >= lc && ld >= lb {
		cc := make([]byte, ld)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < ld; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%lb == 0 {
				ttt = 0
			}
			cc[i] = d[i] ^ a[t] ^ c[tt] ^ b[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	cc := make([]byte, lc)
	i := 0
	t := 0
	tt := 0
	ttt := 0
	for ; i < lc; i++ {
		if i%la == 0 {
			t = 0
		}
		if i%lb == 0 {
			tt = 0
		}
		if i%ld == 0 {
			ttt = 0
		}
		cc[i] = c[i] ^ a[t] ^ b[tt] ^ d[ttt]
		t++
		tt++
		ttt++
	}
	return cc
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
func Hash(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
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
