package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"unsafe"

	// mathrand "math/rand"
	"fmt"
	"time"
)

var (
	Byt = int(32)
)

func main() {
	echo := int(1e3)

	// DXie(echo)
	// DOur(echo)
	// DSutrala(echo)
	// DGuo(echo)
	// DZhang(echo)
	// println()

	ASXie(echo)
	ASOur(echo)
	ASSutrala(echo)
	ASGuo(echo)
	ASZhang(echo)
	println()

	// CSXie(echo)
	// CSOur(echo)
	// CSSutrala(echo)
	// CSGuo(echo)
	// CSZhang(echo)
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

func DSutrala(echo int) { //smart device
	fmt.Print("Sutrala D echo:", echo, "; time:")
	Cert := RS(Byt)
	s := RS(Byt)
	TID := RS(Byt)
	TS := RS(8)
	TS1 := RS(8)
	K1 := RS(Byt)
	R := RS(Byt)
	C := RS(Byt)
	RIDcn := RS(Byt)
	RIDsd := RS(Byt)
	PubRA := RS(Byt)
	PubCN := RS(Byt)
	PubSD := RS(Byt)
	prSD := RS(Byt)
	TCUk := RS(Byt)
	TIDUk := RS(Byt)

	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)

	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		CertCN := Xor(Cert, Hash(concat(TID, s, TS)))
		Hash(concat(TID, s, K1, R, C, CertCN, RIDcn, RIDsd, TS1, TS)) //Xi
		Xor(C, Hash(concat(s, TS, TID, RIDsd)))
		ScalarMul(curve, k, Gx, Gy) //Xi*PubRA
		Hash(concat(RIDcn, PubRA, PubCN))
		ScalarMul(curve, k, Gx, Gy)     //h*RCN
		ScalarMul(curve, k, Gx, Gy)     //Cert*P
		PointAdd(curve, rx, ry, Qx, Qy) //Xi*PubRA+h*RCN
		k2 := RS(Byt)
		TS2 := RS(8)
		kk2 := Hash(concat(k2, s, prSD, TS2))
		ScalarMul(curve, k, Gx, Gy) //k2*P
		Hash(concat(TID, RIDsd, kk2, PubSD, TS2))
		ScalarMul(curve, k, Gx, Gy) //h*kk2
		PointAdd(curve, rx, ry, Qx, Qy)
		ScalarMul(curve, k, Gx, Gy) //k2*K1
		SK := Hash(concat(prSD, Hash(concat(TCUk, TS1)), RIDsd, TIDUk, TS, TS2))
		Hash(concat(SK, TS1, TS2)) //SKV
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}
func ASSutrala(echo int) { //Mobile device
	fmt.Print("Sutrala AS echo:", echo, "; time:")
	Byts := RS(Byt)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Hash(concat(Byts, Byts))                   //sigma_uk
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))  //a*_k
		Hash(concat(Byts, Byts))                   //PIDUk
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))  //prUk
		Xor(Byts, Hash(concat(Byts, Byts)))        //cert
		Hash(concat(Byts, Byts, Byts, Byts, Byts)) //WUk
		RS(Byt)                                    //k1
		TS1 := RS(8)                               //TS1
		Hash(concat(Byts, Byts, Byts))             //k'1
		ScalarMul(curve, k, Gx, Gy)                //K'1
		Xor(Byts, Hash(concat(Byts, Byts, TS1)))   //RIDSD
		Hash(concat(Byts, Byts, Byts, Byts, TS1))
		ScalarMul(curve, k, Gx, Gy)                    //h*k'1
		PointAdd(curve, rx, ry, Qx, Qy)                //cert+
		RS(Byt)                                        //TIDUk
		Xor(Byts, Hash(concat(Byts, Byts, Byts, TS1))) //TID new
		Hash(concat(TS1, Byts, Byts, Byts))            //TCUk
		Xor(Byts, Hash(concat(Byts, TS1, Byts)))

		Hash(concat(Byts, Byts, Byts, Byts))
		ScalarMul(curve, k, Gx, Gy) //h*RSDj
		Hash(concat(Byts, Byts, Byts, Byts, TS1))
		ScalarMul(curve, k, Gx, Gy) //h*K'2
		PointAdd(curve, rx, ry, Qx, Qy)
		ScalarMul(curve, k, Gx, Gy)                                       //Cert*P
		ScalarMul(curve, k, Gx, Gy)                                       //k1*K2
		Hash(concat(Byts, Hash(concat(Byts, TS1)), Byts, Byts, TS1, TS1)) //SK
		Hash(concat(Byts, TS1, TS1))                                      //SKV
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func CSSutrala(echo int) { //controller
	fmt.Print("Sutrala CS echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Hash(concat(Byts, Byts, Byts))
		Hash(concat(Byts, Byts, Byts, Byts, TS))
		ScalarMul(curve, k, Gx, Gy) //h*RUK
		ScalarMul(curve, k, Gx, Gy) //h*K1'
		ScalarMul(curve, k, Gx, Gy) //Cert*P
		PointAdd(curve, rx, ry, Qx, Qy)
		PointAdd(curve, rx, ry, Qx, Qy)
		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Xor(Hash(concat(Byts, Byts)), Hash(concat(Byts, TS, Byts, Byts)))
		Hash(concat(Byts, Byts, Byts, Byts, Byts, Byts, Byts, Byts, TS, TS))
		Xor(Byts, Hash(concat(Byts, Byts, Byts, TS)))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func DGuo(echo int) { //wearable device
	fmt.Print("Guo D echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)

	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)

	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		RS(Byt)
		RS(8)
		Xor(Byts, Hash(concat(Byts, Byts)))
		Hash(concat(Byts, TS, Byts, Byts))

		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Hash(concat(Byts, Byts, Hash(concat(Byts, Byts)), Byts, Byts, TS)) //SK
		Hash(concat(Byts, Byts, Byts, TS))
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}
func ASGuo(echo int) { //User
	fmt.Print("Guo AS echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Xor(Byts, Hash(concat(Byts, Byts)))
		Hash(concat(Byts, Byts))
		Hash(concat(Byts, Byts))
		Xor(Byts, Xor(Byts, Hash(Xor(Byts, Byts))))
		Hash(concat(Byts, Byts, Byts))
		Hash(Xor(Xor(Byts, Byts), Byts))

		Xor(Byts, Hash(Xor(Xor(Byts, Byts), Byts)))
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))
		Hash(concat(Byts, Byts, Byts, Byts))
		Xor(Byts, Hash(concat(Byts, Byts)))
		Hash(concat(Byts, Byts, Byts, Byts, Byts, TS))

		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Xor(Xor(Byts, Hash(Xor(Xor(Byts, Byts), Byts))), Byts)
		Hash(concat(Byts, Byts, Byts, Byts, TS, TS))
		Xor(Byts, Hash(concat(Byts, Byts, Byts, Byts, TS, TS)))
		Hash(concat(Byts, Byts, Byts, TS, TS))
		Hash(concat(Byts, Byts, Byts, TS, TS))
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))

		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Xor(Byts, Hash(concat(Byts, Byts, TS)))
		Hash(concat(Byts, Byts, Byts, Byts, TS))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func CSGuo(echo int) { //server
	fmt.Print("Guo CS echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Xor(Byts, Hash(concat(Byts, Byts)))
		Hash(concat(Byts, Byts, Byts))
		Xor(concat(Byts, Byts, TS))
		Hash(concat(Byts, Byts, Byts, TS))
		Hash(concat(Byts, Byts, Byts, Byts, Byts, TS))

		Hash(concat(Byts, Byts))
		Xor(Byts, Hash(concat(Byts, Byts)))
		Xor(Byts, Hash(Xor(Byts, Byts)))
		Hash(concat(Byts, Byts, Byts, Byts))

		Xor(TS, Hash(concat(Byts, Byts, Byts)))
		Xor(Byts, Hash(concat(Byts, Byts, Byts, TS)))
		Hash(concat(Byts, Byts, Byts, Byts, TS, TS))
		Hash(concat(Byts, Byts, Byts, TS, TS))
		Hash(concat(Byts, Byts, Hash(concat(Byts, Byts)), Byts, Byts, TS))
		Hash(concat(Byts, Byts, Byts, TS, TS))
		Xor(Byts, Hash(concat(Byts, Byts, Byts, Byts, TS, TS)))
		RS(Byt)
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))
		Xor(Byts, Hash(concat(Byts, Byts, Byts)))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func DZhang(echo int) { //wearable device
	fmt.Print("Zhang D echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)

	n := randBits(256)
	x := randBits(256)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	TT(n, x, mod)

	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)

	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Hash(concat(Byts, Byts))                        //sigma1
		Hash(concat(Byts, Byts, Byts))                  //Xi
		Hash(Hash(concat(Byts, Xor(Byts, Byts), Byts))) //Wi
		RS(Byt)                                         //r2
		RS(8)                                           //tau1
		TT(n, x, mod)                                   //C1
		TT(n, x, mod)                                   //C2
		Xor(Byts, Hash(concat(Byts, Xor(Byts, Byts))))  //C3
		Hash(concat(Byts, Byts, Byts, Byts, Byts))      //C4

		TT(n, x, mod) //C9
		Xor(Byts, Byts)
		Hash(concat(Byts, Byts, Byts, TS))
		Hash(concat(Byts, Byts, Byts, TS))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}
func ASZhang(echo int) { //Drone
	fmt.Print("Zhang AS echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)
	n := randBits(256)
	x := randBits(256)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	TT(n, x, mod)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		Xor(Byts, Hash(concat(Byts, TS)))
		TT(n, x, mod)
		Hash(concat(Byts, Byts, Byts, Byts, TS))
		RS(Byt)
		RS(Byt)
		RS(8)
		TT(n, x, mod)
		TT(n, x, mod)
		Xor(Byts, Byts)
		Hash(concat(Byts, Byts, Byts, TS))
		Hash(concat(Byts, Byts, Byts, TS))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

func CSZhang(echo int) { //cc
	fmt.Print("Zhang CS echo:", echo, "; time:")
	Byts := RS(Byt)
	TS := RS(8)
	n := randBits(256)
	x := randBits(256)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	TT(n, x, mod)
	curve := elliptic.P256()
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	k := big.NewInt(12345)
	rx, ry := ScalarMul(curve, k, Gx, Gy)
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	Qx, Qy := curve.ScalarBaseMult(r.Bytes())
	// rx2, ry2 := PointAdd(curve, rx, ry, Qx, Qy)
	PointAdd(curve, rx, ry, Qx, Qy)

	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		TT(n, x, mod)
		TT(n, x, mod)
		TT(n, x, mod)
		Hash(concat(Byts, Byts, Byts))
		Xor(Byts, Hash(concat(Byts, Byts)))
		Hash(concat(Byts, Byts, Byts, Byts, TS))
		RS(Byt)
		RS(8)
		TT(n, x, mod)
		TT(n, x, mod)
		Xor(concat(Byts, Byts, Byts), Hash(concat(Byts, TS)))
		Hash(concat(Byts, Byts, Byts, Byts, TS))
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, "ms ", Ot-ot, "ns")
}

// ---------- Chebyshev chaotic-map ----------
var memo = make(map[string]*big.Int)

func TT(n, x, mod *big.Int) *big.Int {
	for k := range memo {
		delete(memo, k)
	}
	return T(n, x, mod)
}

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

func ScalarMul(curve elliptic.Curve, k *big.Int, px, py *big.Int) (rx, ry *big.Int) {
	if px == nil && py == nil {
		// 使用基点 G
		return curve.ScalarBaseMult(k.Bytes())
	}
	return curve.ScalarMult(px, py, k.Bytes())
}

// PointAdd 计算 P + Q，返回结果点 (rx, ry)
func PointAdd(curve elliptic.Curve, px, py, qx, qy *big.Int) (rx, ry *big.Int) {
	return curve.Add(px, py, qx, qy)
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
