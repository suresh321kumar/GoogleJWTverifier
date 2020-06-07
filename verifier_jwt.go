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
	"crypto"
	"time"
	"strconv"
)

var keys map[string]rsa.PublicKey
var req_pubkey rsa.PublicKey

func main() {
	current_keys := get_publickeys()
	//fmt.Println("The new keys : ", new_keys)

	fmt.Printf("Enter token : ")
	var token_raw string
	fmt.Scanln(&token_raw)

	header, body, signature, msg_hash, req_kid, email, exptime := parseJWT(token_raw)
	fmt.Printf("header : %s\n", header)
	fmt.Printf("body : %s\n", body)
	fmt.Printf("sig : %s\n", signature)
	fmt.Println("msg_hash : ", msg_hash)
	fmt.Println("req_kid : ", req_kid)
	fmt.Println("Email : ", email)
	fmt.Println("exptime : ", exptime)

	req_pubkey := check_publickeys(current_keys, req_kid)	
	fmt.Println("The PublicKey : ", req_pubkey)

	time_now := time.Now().Unix()
	time_expiry,_ := strconv.ParseInt(exptime, 10, 64)

	if time_now < time_expiry {
		fmt.Println("Not expired")
		err := rsa.VerifyPKCS1v15(&req_pubkey, crypto.SHA256, msg_hash, signature)
		if err != nil {
			fmt.Println("Error : ", err)
		} else {
			fmt.Println("Verified !!!!")
		}

	} else {
		fmt.Println("Error : expired token")
	}



}

// func http_handler(w http.ResponseWritter, r *http.request) {
// 	token := r.URL.Query()["token"]

// }






func check_publickeys(keys map[string]rsa.PublicKey, req_kid string) rsa.PublicKey{
	for k,v := range keys {
		//fmt.Println("KID : ",k,"=>","PubKey : ",v)
		if req_kid == k {
			req_pubkey = v
			return req_pubkey
		} 
	}
	
	// get new keys and check again 
	new_keys := get_publickeys()
	for k,v := range new_keys {
		if req_kid == k {
			req_pubkey = v
			return req_pubkey
		} 
	}
	return req_pubkey
}

func parseJWT(token_raw string) ([]byte, []byte, []byte, []byte, string, string, string){

	token_split := strings.Split(token_raw, ".")

	var header = urlsafeB64decode(token_split[0])
	var payload = urlsafeB64decode(token_split[1])
	var signature = urlsafeB64decode(token_split[2])
	//fmt.Printf("header : %s\n", header)
	//fmt.Printf("body : %s\n", payload)
	//fmt.Printf("\n\nSignature : %s\n\n", signature)

	msg_byte := calcSum(token_split[0]+"."+token_split[1])
	//fmt.Println("Message Sum : \n", msg_byte)

	regex_kid := regexp.MustCompile(`.kid...([\w]+).`)
	regex_email := regexp.MustCompile(`\w+@\w+.\w+`)
	regex_exptime := regexp.MustCompile(`.exp.:(\d+)`)

	email := regex_email.FindString(string(payload))
	exptime := regex_exptime.FindStringSubmatch(string(payload))
	header_kid := regex_kid.FindStringSubmatch(string(header))	
	//fmt.Println("The Header kid : ", header_kid[1])
	req_kid := header_kid[1]
	//fmt.Println("The Header kid : ", req_kid)

	//fmt.Printf("Types : %T, %T, %T, %T, %T\n\n", header, payload, signature, msg_byte, req_kid)
	return header, payload, signature, msg_byte, req_kid, email, exptime[1]
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