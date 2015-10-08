package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
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

//Uppercase cause lowercause causes issues when trying to unmarshal
type config struct {
	BcryptRuns        int
	BcryptGoRoutines  int
	NetworkRuns       int
	NetworkGoRoutines int
	FileReadRuns      int
	FileGoRoutines    int
	PrimeRuns         int
	PrimeGoRoutines   int
}

//Globals
var goConfig config

func main() {
	//Load the config file, panics if something goes wrong
	configFile, err := ioutil.ReadFile("config.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(configFile, &goConfig)
	if err != nil {
		panic(err)
	}
	//End init

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
	//Loads the config information and starts a run based on it
	bcryptChannel := make(chan []byte, goConfig.BcryptRuns)
	readFilesChannel := make(chan string, goConfig.FileReadRuns)
	networkChannel := make(chan string, goConfig.NetworkRuns)
	primeNumberChannel := make(chan bool, goConfig.PrimeRuns)

	//Init i cause we will use it later
	var i int
	//Bcrypt
	for i = goConfig.BcryptRuns - goConfig.BcryptGoRoutines; i < goConfig.BcryptRuns; i++ {
		fmt.Println("Running Bcrypt Go")
		go fileBcrypt("./files/story.txt", bcryptChannel)
	}
	for i = goConfig.BcryptRuns - goConfig.BcryptGoRoutines; i > 0; i-- {
		fmt.Println("Running Bcrypt Not-Go")
		fileBcrypt("./files/story.txt", bcryptChannel)
	}
	//End Bcrypt
	//Start files
	for i = goConfig.FileReadRuns - goConfig.FileGoRoutines; i < goConfig.FileReadRuns; i++ {
		fmt.Println("Running File Go")
		go readContents("./files", readFilesChannel)
	}
	for i = goConfig.FileReadRuns - goConfig.FileGoRoutines; i > 0; i-- {
		fmt.Println("Running File Not-Go")
		readContents("./files", readFilesChannel)
	}
	//End files
	//Start network
	for i = goConfig.NetworkRuns - goConfig.NetworkGoRoutines; i < goConfig.NetworkRuns; i++ {
		fmt.Println("Running Network Go")
		go simulateNetworkConnection(networkChannel)
	}
	for i = goConfig.NetworkRuns - goConfig.NetworkGoRoutines; i > 0; i-- {
		fmt.Println("Running Network Not-Go")
		simulateNetworkConnection(networkChannel)
	}
	//End network
	//Start Prime
	for i = goConfig.PrimeRuns - goConfig.PrimeGoRoutines; i < goConfig.PrimeRuns; i++ {
		fmt.Println("Running Prime Go")
		go isPrime(2147483647, primeNumberChannel)
	}
	for i = goConfig.PrimeRuns - goConfig.PrimeGoRoutines; i > 0; i-- {
		fmt.Println("Running Prime Not-Go")
		isPrime(2147483647, primeNumberChannel)
	}
	//End Prime

	<-bcryptChannel
	<-networkChannel
	<-readFilesChannel
	<-primeNumberChannel

	return (time.Now().UnixNano())
}

//Calculates the Md5 of string s and responds with it back on the back channel
func fileBcrypt(fileName string, back chan []byte) {
	file, _ := ioutil.ReadFile(fileName)
	hash, _ := bcrypt.GenerateFromPassword(file, 10)
	back <- hash
}

//Simulates a network latency by sending a response back on the supplied channel after a random number of milliseconds
func simulateNetworkConnection(back chan string) {
	rand.Seed(60)
	time.Sleep(time.Duration((rand.Intn(500) + 150)) * time.Millisecond)
	back <- "ping"
}

//Reads contents of a directory
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
func isPrime(num int, back chan bool) {
	if num <= 1 {
		back <- true
	}
	if num%2 == 0 {
		back <- false
	}
	for i := 3; i < num/2; i = i + 2 {
		if num%i == 0 {
			back <- false
		}
	}
	back <- true
}
