package main

import (
	"fmt"
	b64 "encoding/base64"
	"net/http"
	"strings"
	"regexp"

)

func PrintErrMsg() {
	fmt.Println("ERRERRERRERRERRERR")
}

func handler(w http.ResponseWriter, r *http.Request) {
	// reading the GET request query string and reading only token arg.
	// the commment lines are for debugging
	//queryStr := r.URL.Query()
	//fmt.Println("QUERY : ", queryStr)
	//token := queryStr["token"]
	//fmt.Println("QUERY [token] : ", token[0])
	//fmt.Println("TOKEN : LENGHT : ", len(token[0]))

	token := r.URL.Query()["token"]
	token_split := strings.Split(token[0], ".")


	//Token error handling
	// 1.checking for no token
	// 2.checking for empty token
	// 3.checking whether valid JWT(length of split o/p)

	if token == nil {
		fmt.Println("token not available")
	} else if len(token[0]) < 1 {
		fmt.Println("token empty")
	} else if len(token_split) < 3 {
		fmt.Println("not a valid JWT")
		PrintErrMsg()
	} else {
		var decoded_str,_ = b64.StdEncoding.DecodeString(token_split[1])
		//fmt.Printf("The token decoded : %s\n", decoded_str)

		re_email := regexp.MustCompile(`\w+@\w+.\w+`)
		re_exptime := regexp.MustCompile(`.exp.:(\d+)`)
		email := re_email.FindString(string(decoded_str))
		exptime := re_exptime.FindStringSubmatch(string(decoded_str))
		if email == "" {
			fmt.Println("Invalid JWT or not a Google JWT")
		} else {
			fmt.Printf("The Email : %T, %s\n",email,email)
			fmt.Printf("The Expiry Time : %T, %s \n",exptime, exptime[1])
		}
	}
}


func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
