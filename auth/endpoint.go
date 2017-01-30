// Copyright 2016 Apcera Inc. All rights reserved.

package auth

import (
	// "fmt"
	"bytes"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"github.com/polygon-io/gnatsd/server"
)

// Plain authentication is a basic username and password
type EndpointAuth struct {
	Endpoint 	string
}


type EndpointResp struct {
	Permissions		*server.Permissions		`json:"permissions"`
}

// Create a new multi-user
func NewEndpointAuth( endpoint string ) *EndpointAuth {
	m := &EndpointAuth{Endpoint: endpoint}
	return m
}

// Check authenticates the client using a username and password against a list of multiple users.
func (m *EndpointAuth) Check(c server.ClientAuth) bool {
	opts := c.GetOpts()
	
	// If client has no token, cant authenticate
	if opts.Authorization == "" {
		// fmt.Println("No token..")
		return false
	}

	// Create HTTP Request:
	url := m.Endpoint
	var data = []byte(`{"method":"authorization"}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer "+opts.Authorization)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req); if err != nil {
		// fmt.Println("Authorization Endpoint Error (HTTP call to auth service errored)")
		return false
	}
	defer resp.Body.Close()


	// If we didnt get a 200, not authenticated
	if resp.StatusCode != 200 {
		return false
	}

	// Parse response for User information
	user := server.User{}
	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &user); if err != nil {
		// fmt.Println("Error parsing permissions")
	}

	// Register user and allow connection
	c.RegisterUser(&user)
	return true

}
