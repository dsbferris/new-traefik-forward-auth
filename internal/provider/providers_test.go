package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Utilities

type OAuthServer struct {
	t    *testing.T
	url  *url.URL
	body map[string]string // method -> body
}

func NewOAuthServer(t *testing.T, body map[string]string) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{t: t, body: body}
	server := httptest.NewServer(handler)
	handler.url, _ = url.Parse(server.URL)
	return server, handler.url
}

func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	// fmt.Println("Got request:", r.URL, r.Method, string(body))

	if r.Method == "POST" && r.URL.Path == "/token" {
		if s.body["token"] != string(body) {
			s.t.Fatal("Unexpected request body, expected", s.body["token"], "got", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"123456789"}`)
	} else if r.Method == "GET" && r.URL.Path == "/userinfo" {
		fmt.Fprint(w, `{
			"id":"1",
			"email":"example@example.com",
			"verified_email":true,
			"hd":"example.com"
		}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL, string(body))
	}
}

func TestGetUser(t *testing.T) {
	var testStruct struct {
		Hello string
		World struct {
			This string
			Is   struct {
				A    string
				Test string
			}
		}
	}
	testStruct.Hello = "hello"
	testStruct.World.This = "this"
	testStruct.World.Is.A = "a"
	testStruct.World.Is.Test = "test"
	j, err := json.Marshal(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	v, err := GetUserFromBytes(j, "Hello")
	if err != nil {
		t.Fatal(err)
	}
	if v != testStruct.Hello {
		t.Fatalf("expected %s, got %s", testStruct.Hello, v)
	}

	v, err = GetUserFromBytes(j, "World.This")
	if err != nil {
		t.Fatal(err)
	}
	if v != testStruct.World.This {
		t.Fatalf("expected %s, got %s", testStruct.World.This, v)
	}

	v, err = GetUserFromBytes(j, "World.Is.A")
	if err != nil {
		t.Fatal(err)
	}
	if v != testStruct.World.Is.A {
		t.Fatalf("expected %s, got %s", testStruct.World.Is.A, v)
	}
}
