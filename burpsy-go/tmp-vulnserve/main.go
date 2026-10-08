package main

import (
	"fmt"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func main() {
	fmt.Println("vulnapp on 127.0.0.1:18300")
	if err := http.ListenAndServe("127.0.0.1:18300", vulnapp.Handler()); err != nil {
		fmt.Println("ERR:", err)
	}
}
