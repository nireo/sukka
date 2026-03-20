package main

import (
	"log"

	"github.com/nireo/sukka"
)

func main() {
	s := &sukka.Server{Addr: ":1080"}
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
