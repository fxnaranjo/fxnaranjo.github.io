package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"unicode"
)

type SoapEnvelopeDelete struct {
	XMLName xml.Name `xml:"soapenv:Envelope"`
	Annon   string   `xml:"xmlns:soapenv,attr"`
	Header  Header   `xml:"soapenv:Header"`
	Body    Body     `xml:"soapenv:Body"`
}

type Header struct {
}

type Body struct {
	Request Request `xml:"dp:request"`
}

type Request struct {
	Action Action `xml:"dp:do-action"`
	Annon  string `xml:"xmlns:dp,attr"`
	Annon2 string `xml:"domain,attr"`
}

type Action struct {
	Delete interface{}
	Add    interface{}
	Save   interface{}
}

type AddPasswordMap struct {
	XMLName   xml.Name `xml:"AddPasswordMap"`
	AliasName string   `xml:"AliasName"`
	Password  string   `xml:"Password"`
}

type DeletePasswordMap struct {
	XMLName   xml.Name `xml:"DeletePasswordMap"`
	AliasName string   `xml:"AliasName"`
}

type SaveConfig struct {
	XMLName xml.Name `xml:"SaveConfig"`
}

// Define the structures based on the XML structure
type Envelope struct {
	Body BodyResponse `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

type BodyResponse struct {
	Response Response `xml:"http://www.datapower.com/schemas/management response"`
}

type Response struct {
	Timestamp string   `xml:"timestamp"`
	Result    []string `xml:"result"` // Slice to capture multiple <result> elements
}

func printUsage() {
	log.Println("****************************************** U S A G E ****************************************************************")
	log.Println("go run passwordAlias.go")
	log.Println("######### ARGUMENTS #########")
	log.Println("-dpAddress=<Datapower IP Address>")
	log.Println("-port=<Datapower SOMA Port>")
	log.Println("-dpUser=<Datapower User> ")
	log.Println("-dpPassword=<Datapower Password>")
	log.Println("-domain=<Datapower Domain> ")
	log.Println("-alias=<Password Alias Name>")
	log.Println("-aliasPassword=<New Password for Alias>")
	log.Println("-v for debug")
	log.Println("Example: go run passwordAlias.go --dpAddress=192.168.0.1 -port 5550 -dpUser admin -dpPassword mypassw0rd -domain default -alias DB2User -aliasPassword mypassw0rd")
	log.Println("*********************************************************************************************************************")
}

func validateArgument(argument string, isclosed bool, values []string) (result bool) {
	response := true
	if !isclosed {
		if argument == "" {
			response = false
		}
	} else {
		if argument == "" || !slices.Contains(values, argument) {
			response = false
		}
	}

	return response
}

func isInt(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func getAddPasswordMap(username string, password string) (passwordMap AddPasswordMap) {
	addPasswordMap := AddPasswordMap{AliasName: username, Password: password}
	return addPasswordMap
}

func getDeletePasswordMap(username string) (passwordMap DeletePasswordMap) {
	daletePasswordMap := DeletePasswordMap{AliasName: username}
	return daletePasswordMap
}

func printResponseBody(mybody []byte) {

	//Convert the body to type string
	sb := string(mybody)

	log.Println("****************************D E B U G************************************")
	log.Println(sb)
	log.Println("*************************************************************************")
}

func cleanText(text string) string {

	// Remove line breaks and spaces
	cleanedStr := strings.ReplaceAll(text, "\n", "")     // Remove line breaks
	cleanedStr = strings.ReplaceAll(cleanedStr, " ", "") // Remove spaces

	return cleanedStr
}
func printResults(data []byte) {
	var envelope Envelope

	// Unmarshal the XML data
	err := xml.Unmarshal([]byte(data), &envelope)
	if err != nil {
		log.Println("Error unmarshalling XML:", err)
		os.Exit(1)
	}

	// Print extracted information
	log.Println("Timestamp:", envelope.Body.Response.Timestamp)
	log.Println("******* Results *******")

	for counter, result := range envelope.Body.Response.Result {
		myResult := cleanText(result)
		switch counter {
		case 0:
			if myResult != "OK" {
				log.Println("Password Alias was NOT Present")
			} else {
				log.Println("Password Alias Deleted: " + myResult)
			}
		case 1:
			log.Println("Password Alias Created: " + myResult)
		case 2:
			log.Println("Datapower Configuration Saved: " + myResult)
		}
	}
}

func updatePasswordAlias(datapower string, port string, username string, password string, domain string, aliasName string, newPassword string, debug bool) {

	// Create a custom Transport that skips TLS validation
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Ignore TLS certificate validation
		},
	}

	//HTTP Client for request
	client := &http.Client{
		Transport: transport,
	}

	deletePasswordMap := getDeletePasswordMap(aliasName)
	addPasswordMap := getAddPasswordMap(aliasName, newPassword)
	saveConfig := SaveConfig{}

	action := Action{Delete: deletePasswordMap, Add: addPasswordMap, Save: saveConfig}

	request := Request{Annon: "http://www.datapower.com/schemas/management", Annon2: domain, Action: action}

	body := Body{Request: request}

	header := Header{}

	soapEnvelope := SoapEnvelopeDelete{Annon: "http://schemas.xmlsoap.org/soap/envelope/", Header: header, Body: body}

	xmlData, err := xml.Marshal(soapEnvelope)
	if err != nil {
		panic(err)
	}

	protocol := "https://"
	END_POINT := protocol + datapower + ":" + port

	//Confugure the HTTP request options
	bodyReader := bytes.NewReader([]byte(xmlData))

	req, err := http.NewRequest("POST", END_POINT, bodyReader)
	req.SetBasicAuth(username, password)

	//Execute the request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
		os.Exit(0)
	}

	//Analize the response code of the call
	log.Println("Status:", resp.StatusCode)

	defer resp.Body.Close()

	mybody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}

	printResults(mybody)

	if debug {
		printResponseBody(mybody)
	}

}

func main() {

	DATAPOWER_IP := flag.String("dpAddress", "", "DataPower IP Address")
	PORT := flag.String("port", "", "DataPower SOMA Port")
	DATAPOWER_USER := flag.String("dpUser", "", "DataPower User")
	DATAPOWER_PASSWORD := flag.String("dpPassword", "", "DataPower Password")
	DOMAIN := flag.String("domain", "", "DataPower Domain")
	ALIAS := flag.String("alias", "", "DataPower Alias User")
	ALIAS_PASSWORD := flag.String("aliasPassword", "", "DataPower Alias Password")
	DEBUG := flag.Bool("v", false, "Debug")

	flag.Parse()

	dpAddress := strings.ToLower(*DATAPOWER_IP)
	port := strings.ToLower(*PORT)
	dpUser := strings.ToLower(*DATAPOWER_USER)
	dpPassword := strings.ToLower(*DATAPOWER_PASSWORD)
	domain := strings.ToLower(*DOMAIN)
	alias := strings.Trim(*ALIAS, " ")
	aliasPassword := strings.Trim(*ALIAS_PASSWORD, " ")
	debug := bool(*DEBUG)

	validate := 1

	if !validateArgument(dpAddress, false, nil) {
		log.Println("Datapower IP Address was not specified")
		validate = 0
	} else {
		if !validateArgument(port, false, nil) {
			log.Println("Datapower PORT was not specified")
			validate = 0
		} else {
			if !isInt(port) {
				log.Println("Datapower PORT is not valid")
				validate = 0
			} else {
				if !validateArgument(dpUser, false, nil) {
					log.Println("Datapower User was not specified")
					validate = 0
				} else {
					if !validateArgument(dpPassword, false, nil) {
						log.Println("Datapower Password was not specified")
						validate = 0
					} else {
						if !validateArgument(domain, false, nil) {
							log.Println("Datapower Domain was not specified")
							validate = 0
						} else {
							if !validateArgument(alias, false, nil) {
								log.Println("Datapower Password Alias was not specified")
								validate = 0
							} else {
								if !validateArgument(aliasPassword, false, nil) {
									log.Println("Datapower Password Alias New Password was not specified")
									validate = 0
								}
							}
						}
					}
				}
			}
		}
	}

	if validate == 0 {
		printUsage()
		os.Exit(0)
	}

	updatePasswordAlias(dpAddress, port, dpUser, dpPassword, domain, alias, aliasPassword, debug)

	log.Println("PROCESS COMPLETED")

}
