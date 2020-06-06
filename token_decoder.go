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
	token := r.URL.Query()["token"]
	token_split := strings.Split(token[0], ".")
	var decoded_str,_ = b64.StdEncoding.DecodeString(token_split[1])

	re_email := regexp.MustCompile(`\w+@\w+.\w+`)
	re_exptime := regexp.MustCompile(`.exp.:(\d+)`)
	email := re_email.FindString(string(decoded_str))
	exptime := re_exptime.FindStringSubmatch(string(decoded_str))

	time_now := time.Now().Unix()
	time_expiry,_ := strconv.ParseInt(exptime[1], 10, 64) 

	if time_now < time_expiry {
		fmt.Fprintf(w,email)
	} else {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error : expired token")
	}
}


func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
