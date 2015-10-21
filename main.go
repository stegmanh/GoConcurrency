package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
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

	//TCP server
	go startAndRunTCPServer()
	//End TCP server func

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

//Starts a TCP server listening on port 8000
//We listen for requests with ln.Accept and when we get one, we handleTCPConn in another goroutine
func startAndRunTCPServer() {
	conns := make([]net.Conn, 0, 100)
	ln, err := net.Listen("tcp", ":8000")
	if err != nil {
		fmt.Println(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting the connection ", err)
			continue
		}
		broadCast("A new client has connected", conns)
		conns = append(conns, conn)
		go handleTCPConn(conn)
	}
}

//Creates a reader form the conection
//Reads new string with ReadString delimited with '\n'.
//	If there is an error (EOF when client DC) we close the connection and return out of the goroutine
func handleTCPConn(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			fmt.Println("Client has closed the connection ", conn.RemoteAddr())
			return
		}
		message = "We recieved message " + message + "\n"
		conn.Write([]byte(message))
	}
}

func broadCast(message string, conns []net.Conn) {
	for _, conn := range conns {
		fmt.Fprintf(conn, message+"\n")
	}
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
		//fmt.Println("Running Bcrypt Go")
		go fileBcrypt("./files/story.txt", bcryptChannel)
	}
	for i = goConfig.BcryptRuns - goConfig.BcryptGoRoutines; i > 0; i-- {
		//fmt.Println("Running Bcrypt Not-Go")
		fileBcrypt("./files/story.txt", bcryptChannel)
	}
	//End Bcrypt
	//Start files
	for i = goConfig.FileReadRuns - goConfig.FileGoRoutines; i < goConfig.FileReadRuns; i++ {
		//fmt.Println("Running File Go")
		go readContents("./files", readFilesChannel)
	}
	for i = goConfig.FileReadRuns - goConfig.FileGoRoutines; i > 0; i-- {
		//fmt.Println("Running File Not-Go")
		readContents("./files", readFilesChannel)
	}
	//End files
	//Start network
	for i = goConfig.NetworkRuns - goConfig.NetworkGoRoutines; i < goConfig.NetworkRuns; i++ {
		//fmt.Println("Running Network Go")
		go simulateNetworkConnection(networkChannel)
	}
	for i = goConfig.NetworkRuns - goConfig.NetworkGoRoutines; i > 0; i-- {
		//fmt.Println("Running Network Not-Go")
		simulateNetworkConnection(networkChannel)
	}
	//End network
	//Start Prime //Ad 47 to end of numbers to make SUPER slow
	for i = goConfig.PrimeRuns - goConfig.PrimeGoRoutines; i < goConfig.PrimeRuns; i++ {
		//fmt.Println("Running Prime Go")
		go isPrime(21474836, primeNumberChannel)
	}
	for i = goConfig.PrimeRuns - goConfig.PrimeGoRoutines; i > 0; i-- {
		//fmt.Println("Running Prime Not-Go")
		isPrime(21474836, primeNumberChannel)
	}
	//End Prime

	//End the channel
	for i = 0; i < goConfig.BcryptRuns; i++ {
		<-bcryptChannel
	}
	for i = 0; i < goConfig.NetworkRuns; i++ {
		<-networkChannel
	}
	for i = 0; i < goConfig.NetworkRuns; i++ {
		<-readFilesChannel
	}
	for i = 0; i < goConfig.PrimeRuns; i++ {
		<-primeNumberChannel
	}

	return (time.Now().UnixNano())
}

//Calculates the Md5 of string s and responds with it back on the back channel
func fileBcrypt(fileName string, back chan []byte) {
	file, _ := ioutil.ReadFile(fileName)
	hash, _ := bcrypt.GenerateFromPassword(file, 5)
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
		return
	}
	if num%2 == 0 {
		back <- false
		return
	}
	for i := 3; i < num/2; i = i + 2 {
		if num%i == 0 {
			back <- false
			return
		}
	}
	back <- true
	return
}
