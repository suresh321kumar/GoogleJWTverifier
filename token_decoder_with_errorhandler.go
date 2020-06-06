package main

import (
	"fmt"
	b64 "encoding/base64"
	"net/http"
	"strings"
	"regexp"
	"time"
	"strconv"

)

func handler(w http.ResponseWriter, r *http.Request) {
	// reading the GET request query string and reading only token arg.
	// the commment lines are for debugging
	//queryStr := r.URL.Query()
	//fmt.Println("QUERY : ", queryStr)
	//token := queryStr["token"]
	//fmt.Println("QUERY [token] : ", token[0])
	//fmt.Println("TOKEN : LENGHT : ", len(token[0]))

	token := r.URL.Query()["token"]


	//Token error handling
	// 1.checking for no token
	// 2.checking for empty token
	// 3.checking whether valid JWT(length of split o/p)

	if token == nil {
		//fmt.Println("Error: Token not available")
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error : Token not available\n")
	} else if len(token[0]) < 1 {
		//fmt.Println("Error: Token is empty")
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error : Token is empty\n")

	} else {
		token_split := strings.Split(token[0], ".")
		if len(token_split) < 3 {
			//fmt.Println("Not a valid JWT")
			w.WriteHeader(400)
			fmt.Fprintf(w, "Error : Not a valid JWT\n")
		} else {
			var decoded_str,_ = b64.StdEncoding.DecodeString(token_split[1])
			//fmt.Printf("The token decoded : %s\n", decoded_str)

			re_email := regexp.MustCompile(`\w+@\w+.\w+`)
			re_exptime := regexp.MustCompile(`.exp.:(\d+)`)
			email := re_email.FindString(string(decoded_str))
			exptime := re_exptime.FindStringSubmatch(string(decoded_str))
			if email == "" {
				//fmt.Println("Error : Invalid JWT or not a Google JWT")
				w.WriteHeader(400)
				fmt.Fprintf(w, "Error : Invalid JWT or not a Google JWT\n")
			} else {
				time_now := time.Now().Unix()
				time_expiry,_ := strconv.ParseInt(exptime[1], 10, 64) 
				if time_now < time_expiry {
					//fmt.Println("Token Valid")
					fmt.Fprintf(w,email)
				} else {
					//fmt.Println("Token expired")
					w.WriteHeader(400)
					fmt.Fprintf(w, "Error : expired token")
				}
				//fmt.Printf("The Email : %T, %s\n",email,email)
				//fmt.Printf("The Expiry Time : %s \n", exptime[1])
				//fmt.Printf("The Current Time : %d \n",time_now)
				//fmt.Fprintf(w, "hello")
			}
		}
	}
}


func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
