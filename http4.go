package main

import (
	"fmt"
	"log"
	"net/url"
)

func main() {
	//u, err := url.Parse("https://example.org/?name=suresh&last=kumar&dob=24101998")
	u, err := url.Parse("https://example.org/")
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	fmt.Println(q["name"])
	fmt.Println(q.Get("last"))
	fmt.Println(q)
}

