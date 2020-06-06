package main

import (
	"fmt"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"bytes"
	"io"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
)

func main() {
	b64_n := "wl6TaY_3dsuLczYH_hioeQ5JjcLKLGYb--WImN9_IKMkOj49dgs25wkjsdI9XGJYhhPJLlvfjIfXH49ZGA_XKLx7fggNaBRZcj1y-I3_77tVa9N7An5JLq3HT9XVt0PNTq0mtX009z1Hva4IWZ5IhENx2rWlZOfFAXiMUqhnDc8VY3lG7vr8_VG3cw3XRKvlZQKbb6p2YIMFsUwaDGL2tVF4SkxpxIazUYfOY5lijyVugNTslOBhlEMq_43MZlkznSrbFx8ToQ2bQX4Shj-r9pLyofbo6A7K9mgWnQXGY5rQVLPYYRzUg0ThWDzwHdgxYC5MNxKyQH4RC2LPv3U0LQ"

	b64_e := "AQAB"

	//n,_ := base64.URLEncoding.DecodeString(b64_n)
	//fmt.Println("N: ", n)

	n_int := byteToInt(urlsafeB64decode(b64_n))
	//n_int.SetBytes(n)
	fmt.Println("N_Int : ", n_int)

	e,_ := base64.URLEncoding.DecodeString(b64_e)
	fmt.Println("E: ", e)

	//e_reader := bytes.NewReader(e)
	//fmt.Println("E_reader : ", e_reader)
	//var e_io_reader io.Reader = e_reader
	//var e_int uint6r
	//binary.Read(e_io_reader, binary.BigEndian, &e_int)
	//fmt.Println("E_int : ", int(e_int))

	e_btr := byteToBtr(e)
	fmt.Println("E_btr: ", e_btr)
	e_int := btrToInt(e_btr)
	fmt.Println("E_int: ", e_int)

	public_key := rsa.PublicKey{N: n_int,E: e_int}
	fmt.Printf("Public key: %q, %T", public_key,public_key)

	fmt.Printf("Enter token : ")
	var token_raw string
	fmt.Scanln(&token_raw)
	token_split := strings.Split(token_raw, ".")

	var header = urlsafeB64decode(token_split[0])
	var body = urlsafeB64decode(token_split[1])
	var signature = urlsafeB64decode(token_split[2])
	fmt.Printf("header : %s\n", header)
	fmt.Printf("body : %s\n", body)
	fmt.Printf("\n\nSignature : %s\n\n", signature)
	
	//msgToSign := token_split[0] + "." + token_split[1]
	//fmt.Printf("Message To sign : %s\n", msgToSign)

//	msg_sum := sha256.New()
//	msg_sum.Write([]byte(msgToSign))
	msg_byte := calcSum(token_split[0]+"."+token_split[1])
	fmt.Println("Message Sum : \n", msg_byte)

	err := rsa.VerifyPKCS1v15(&public_key, crypto.SHA256, msg_byte, signature)
	if err != nil {
		fmt.Println("Error : ", err)
	} else {
		fmt.Println("Verified ?")
	}
}


func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}
func btrToInt(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}
func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}
func calcSum(str string) []byte {
	a := sha256.New()
	a.Write([]byte(str))
	return a.Sum(nil)
}
func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}
