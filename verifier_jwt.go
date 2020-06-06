package main 

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"regexp"
	"bytes"
	"math/big"
	"encoding/base64"
	"encoding/binary"
	"crypto/sha256"
	"crypto/rsa"
	"io"
	"strings"
)

var keys map[string]rsa.PublicKey

func main() {
	new_keys := get_publickeys()
	fmt.Println("The new keys : ", new_keys)
}


func get_publickeys() map[string]rsa.PublicKey {
	jwk_get_resp,_ := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	jwk_cont,_ := ioutil.ReadAll(jwk_get_resp.Body)

	// cont_string := string(content)
	// resp.Body.Close()
	// fmt.Println("The body : ", cont_string)	

	regex_kid := regexp.MustCompile(`"kid": "(\S+)"`)
	regex_n := regexp.MustCompile(`"n": "(\S+)"`)
	regex_e := regexp.MustCompile(`"e": "(\S+)"`)

	kid := regex_kid.FindAllSubmatch(jwk_cont, -1)
	n := regex_n.FindAllSubmatch(jwk_cont, -1)
	e := regex_e.FindAllSubmatch(jwk_cont, -1)

	// fmt.Printf("\nThe KID-1 : %s\n", kid[0][1])
	// fmt.Printf("\nThe N-1 : %s\n", n[0][1])
	// fmt.Printf("\nThe E-1 : %s\n\n\n", e[0][1])

	// fmt.Printf("\nThe KID-2 : %s\n", kid[1][1])
	// fmt.Printf("\nThe N-2 : %s\n", n[1][1])
	// fmt.Printf("\nThe E-2 : %s\n", e[1][1])

	n1 := byteToInt(urlsafeB64decode(string(n[0][1])))
	//fmt.Printf("\nThe N-1 : %s\n", n1)
	n2 := byteToInt(urlsafeB64decode(string(n[1][1])))
	//fmt.Printf("\nThe N-2 : %s\n", n2)

	e1 := btrToInt(byteToBtr(urlsafeB64decode(string(e[0][1]))))
	//fmt.Printf("\nThe E-1 : %d\n", e1)
	e2 := btrToInt(byteToBtr(urlsafeB64decode(string(e[1][1]))))
	//fmt.Printf("\nThe E-2 : %d\n", e2)

	public_key1 := rsa.PublicKey{N:n1, E:e1}
	//fmt.Println("The PublicKey-1 : ", public_key1)
	public_key2 := rsa.PublicKey{N:n2, E:e2}
	//fmt.Println("The PublicKey-2 : ", public_key2)

	keys := map[string]rsa.PublicKey{
		string(kid[0][1]):public_key1,
		string(kid[1][1]):public_key2,
	}
	//fmt.Println("The Keys : ", keys)

	return keys
}

















//////////////////////// Helper Functions ////////////////////////////////////
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