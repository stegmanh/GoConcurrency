package main

import (
	"bufio"
	"crypto/md5"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"hash"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	//"strings"
	"time"
)

//Response struct we will send to the client
type Response struct {
	RequestRecievedAt int64
	ResponseSentAt    int64
	TimeToProcess     int64
}

//Struct names are uppercase because lowercase causes issues with unmarshalling
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

//Struct wrapper to keep track of client connections
type clientTCPConnection struct {
	conn          net.Conn
	messageCount  int
	authenticated bool
	started       bool
}

//Result struct stores the information recieved back from the clients
type result struct {
	Mean  int64
	Total int64
	Max   int64
	Min   int64
}

//Results is just a struct that contains an [] of result
type results struct {
	Results []result
}

//Crypto globals - get initialized in main function
var privateKey *rsa.PrivateKey
var publicKeyPKIX []byte
var hashInterface hash.Hash
var blankLabel []byte

//General global
var goConfig config
var finishChannel chan result

var runResults results

func main() {
	//Load the config file, panics if something goes wrong
	//Reads the file, takes the resulting []bytes and unmarshals it into the config struct
	configFile, err := ioutil.ReadFile("config.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(configFile, &goConfig)
	if err != nil {
		panic(err)
	}
	//End init

	//Inits the crypto information - public/private key
	privateKey, publicKeyPKIX, err = generateRSAInformation()
	if err != nil {
		panic(err)
	}

	//Start tcp server listener in a goroutine
	go startAndRunTCPServer()

	//The default HTTP handler
	//Listens to requests at '/', for each request it takes note of the time recieved
	//Then it kicks off the set of nonTrivialTasks and stores the time it took in responseSent
	//Server listening on port 8080
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
	//Map of clients
	clients := make(map[string]net.Conn)
	ln, err := net.Listen("tcp", ":8000")
	if err != nil {
		fmt.Println(err)
	}

	//Time.after will call a function after some amount of time passes
	//The function called will make a map of all currently connected clients and broadcast a start message to them
	time.AfterFunc(time.Second*10, func() {
		fmt.Printf("Requesting %d clients to start\n", len(clients))
		currentConns := make(map[string]net.Conn)
		for k, v := range clients {
			currentConns[k] = v
		}
		handleStartedClients(currentConns)
	})

	//TCP server listener
	//Accepts connections and handles each in a seperate goroutine with handleTCPConn
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting the connection ", err)
			continue
		}
		clients[conn.RemoteAddr().String()] = conn
		go handleTCPConn(conn, clients)
	}
}

//Function to handle clients currently hitting server
//We init finishChannel and numberOfFinishedClients to block until all clients have finished their requests
func handleStartedClients(conns map[string]net.Conn) {
	finishChannel = make(chan result, len(conns))
	broadCast("start\n", conns)
	var numberOfFinishedClients int
	for numberOfFinishedClients < len(conns) {
		runResults.Results = append(runResults.Results, <-finishChannel)
		numberOfFinishedClients++
	}
	fmt.Printf("Finished all requests with %+v", runResults.summarize())
}

//Creates a reader form the conection
//Reads new string with ReadString delimited with '\n'.
//If there is an error (EOF when client DC) we close the connection and return out of the goroutine
func handleTCPConn(conn net.Conn, conns map[string]net.Conn) {
	reader := bufio.NewReader(conn)
	clientConnection := clientTCPConnection{conn: conn, messageCount: 0, authenticated: false}
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			delete(conns, conn.RemoteAddr().String())
			fmt.Println("Client has closed the connection ", conn.RemoteAddr())
			return
		}
		handleMessage(message, &clientConnection)
	}
}

//Refactor to have first message send pkey, the decrypt then have a case to handle different messages
func handleMessage(message string, clientConnection *clientTCPConnection) {
	clientConnection.messageCount++
	//Handle first message
	if clientConnection.messageCount == 1 {
		message = message[0 : len(message)-2]
		base64PublicKey := base64.StdEncoding.EncodeToString(publicKeyPKIX)
		fmt.Fprintf(clientConnection.conn, "RSAKEY::%s\n", base64PublicKey)
		return
	}
	unEncodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		fmt.Println("Error unencoding message ", err)
		return
	}
	unencryptedMessage, err := rsa.DecryptOAEP(hashInterface, cRand.Reader, privateKey, unEncodedMessage, blankLabel)
	if err != nil {
		fmt.Println("Error decrypting message ", err)
		return
	}
	switch {
	case !clientConnection.authenticated:
		if string(unencryptedMessage) == "TESTPASS" {
			clientConnection.authenticated = true
		}
		fmt.Println("Authenticated successfully ")
	case clientConnection.authenticated:
		switch {
		case !clientConnection.started:
			if string(unencryptedMessage) == "starting" {
				clientConnection.started = true
			}
		case clientConnection.started:
			if strings.HasPrefix(string(unencryptedMessage), "done") {
				unencryptedMessage = []byte(strings.TrimPrefix(string(unencryptedMessage), "done:"))
				var runResult result
				err := json.Unmarshal(unencryptedMessage, &runResult)
				if err != nil {
					fmt.Println("ERROR ERROR ERROR!!!", err)
				}
				clientConnection.started = false
				finishChannel <- runResult
			}
		}
	default:
		fmt.Fprintf(clientConnection.conn, "Unauthenticated clients not supported")
	}
}

func broadCast(message string, conns map[string]net.Conn) {
	for _, conn := range conns {
		fmt.Fprintf(conn, message+"\n")
	}
}

func generateRSAInformation() (*rsa.PrivateKey, []byte, error) {
	hashInterface = md5.New()
	privateKey, err := rsa.GenerateKey(cRand.Reader, 2014)
	if err != nil {
		return nil, make([]byte, 0), err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, make([]byte, 0), err
	}

	publicKeyFromPrivate := privateKey.Public()
	bytes, err := x509.MarshalPKIXPublicKey(publicKeyFromPrivate)
	if err != nil {
		return nil, make([]byte, 0), err
	}
	return privateKey, bytes, nil
}

func (r results) summarize() result {
	summary := result{Mean: 0, Max: -1, Min: 1<<63 - 1}
	for _, res := range r.Results {
		summary.Max = max(res.Max, summary.Max)
		summary.Min = min(res.Min, summary.Min)
		summary.Total += res.Total
	}

	return summary
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

func min(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
