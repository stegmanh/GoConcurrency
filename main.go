package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

//Response is a response.. Consider adding an error field of type Error
type Response struct {
	RequestRecievedAt int64
	ResponseSentAt    int64
	TimeToProcess     int64
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestRecieved := time.Now().UnixNano()
		responseSent := nonTrivialTast(r)
		resp := Response{RequestRecievedAt: requestRecieved, ResponseSentAt: responseSent, TimeToProcess: responseSent - requestRecieved}
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			fmt.Println("Error encoding JSON: ", err)
		}
	})
	fmt.Println("Starting server..")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

//Runs a non trivial task and returns the time it finished
func nonTrivialTast(r *http.Request) int64 {
	md5Channel := make(chan [16]byte, 1)
	networkChanel := make(chan string, 1)
	readFilesChannel := make(chan string, 1)

	go readContents("./files", readFilesChannel)
	fileMd5(fmt.Sprint(r), md5Channel)
	simulateNetworkConnection(networkChanel)

	<-md5Channel
	<-networkChanel
	<-readFilesChannel

	return (time.Now().UnixNano())
}

//Calculates the Md5 of string s and responds with it back on the back channel
func fileMd5(s string, back chan [16]byte) {
	back <- md5.Sum([]byte(s))
}

//Simulates a network latency by sending a response back on the supplied channel after a random number of milliseconds
func simulateNetworkConnection(back chan string) {
	rand.Seed(60)
	time.Sleep(time.Duration((rand.Intn(3) + 5)) * time.Millisecond)
	back <- "ping"
}

func readContents(dir string, back chan string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Println("error reading dir: ", err)
		back <- "pong"
	}
	for _, file := range files {
		ioutil.ReadFile(file.Name())
	}
	back <- "ping"
}

//Returns if a prime number
func isPrime(num int) bool {
	if num <= 1 {
		return true
	}
	if num%2 == 0 {
		return false
	}
	for i := 3; i < num/2; i = i + 2 {
		if num%i == 0 {
			return false
		}
	}
	return true
}
