package main

// Note: This was built off of an example reverse proxy created by Ben Church
// https://github.com/bechurch/reverse-proxy-demo

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"

	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	auth_endpoint_url         string
	auth_client_id            string
	auth_client_secret        string
	auth_scope                string
	proxy_downstream_url      string
	proxy_downstream_wss      string
	proxy_port                string
	access_token              string
	token_type                string
	token_refresh_time        time.Time
	downstream_api_key        string
	downstream_api_key_header string
	inbound_api_key           string
	debug_enabled             bool
)

// Checks that the incoming request carries "Authorization: Bearer <INBOUND_API_KEY>"
func isClientAuthorized(req *http.Request) bool {
	scheme, token, found := strings.Cut(req.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(inbound_api_key)) == 1
}

func isWebSocketRequest(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func logDebug(format string, v ...any) {
	if debug_enabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Returns a copy of the headers with sensitive values masked
func redactHeaders(h http.Header) http.Header {
	redacted := h.Clone()
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", downstream_api_key_header} {
		if name != "" && redacted.Get(name) != "" {
			redacted.Set(name, "**************")
		}
	}
	return redacted
}

// Structure for storing results from a
type AuthReponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// Proxies the incoming request to the downstream, adding Authorization
// header and optional API Key header
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	websocket := isWebSocketRequest(req)
	target := proxy_downstream_url
	if websocket {
		target = proxy_downstream_wss
	}

	url, err := url.Parse(target)
	if err != nil {
		log.Print(err)
		http.Error(res, "Failure calling downstream proxy", http.StatusInternalServerError)
		return
	}
	// The HTTP transport only understands http/https; the WebSocket handshake is a plain HTTP request
	switch strings.ToLower(url.Scheme) {
	case "ws":
		url.Scheme = "http"
	case "wss":
		url.Scheme = "https"
	}

	start := time.Now()
	logDebug("Incoming %s %s from %s (Content-Length: %d)", req.Method, req.RequestURI, req.RemoteAddr, req.ContentLength)
	logDebug("Incoming headers: %v", redactHeaders(req.Header))

	if !isClientAuthorized(req) {
		log.Printf("Unauthorized %s %s from %s: missing or invalid inbound API key", req.Method, req.RequestURI, req.RemoteAddr)
		res.Header().Set("WWW-Authenticate", `Bearer realm="proxy"`)
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("Downstream %s %s -> %s (%s)", resp.Request.Method, resp.Request.URL, resp.Status, time.Since(start))
		logDebug("Downstream response headers: %v", redactHeaders(resp.Header))
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Downstream error for %s %s after %s: %v", r.Method, r.URL, time.Since(start), err)
		rw.WriteHeader(http.StatusBadGateway)
	}

	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Host = url.Host

	req.Header.Set("Authorization", token_type+" "+access_token)

	// Never forward a client-supplied downstream API key
	req.Header.Del(downstream_api_key_header)
	if downstream_api_key != "" {
		req.Header.Set(downstream_api_key_header, downstream_api_key)
	}

	if websocket {
		log.Printf("Proxy WebSocket %s %s", req.Method, req.URL)
	} else {
		log.Printf("Proxy %s %s", req.Method, req.URL)
	}
	logDebug("Outgoing headers: %v", redactHeaders(req.Header))
	proxy.ServeHTTP(res, req)
}

// Gets (or refreshes) the access token using a jittered backed-off retry
func getOuath2AuthAccessToken() {
	request_body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {auth_client_id},
		"client_secret": {auth_client_secret},
	}
	if auth_scope != "" {
		request_body.Set("scope", auth_scope)
	}

	retry_number := -1

	for {
		retry_number++

		if retry_number > 5 {
			log.Print("Failed to acquire access token; exiting")
			break
		} else if retry_number > 0 {
			seconds_to_wait := retry_number*retry_number + 1
			log.Printf("Failed to aquired token; awaiting retry #%v in %v seconds", retry_number, seconds_to_wait)
			retry_time := time.Duration(seconds_to_wait) * time.Second
			time.Sleep(retry_time)
			log.Printf("Retry #%v", retry_number)
		}

		log.Printf("Sending authentication request via POST to %s", auth_endpoint_url)
		resp, err := http.PostForm(auth_endpoint_url, request_body)

		if err != nil {
			log.Print(err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Print(err)
			continue
		}

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			log.Printf("Received non-200 status code: %s", resp.Status)
			log.Printf("Authentication error response body: %s", body)
			continue
		}
		logDebug("Authentication response status: %s, body length: %d", resp.Status, len(body))

		auth_response := AuthReponse{}
		err = json.Unmarshal(body, &auth_response)
		if err != nil {
			var syntax_err *json.SyntaxError
			var type_err *json.UnmarshalTypeError
			switch {
			case errors.As(err, &syntax_err):
				log.Printf("Authentication response is not valid JSON (offset %d, Content-Type %q): %v", syntax_err.Offset, resp.Header.Get("Content-Type"), err)
			case errors.As(err, &type_err):
				log.Printf("Authentication response field %q has type %s, expected %s", type_err.Field, type_err.Value, type_err.Type)
			default:
				log.Printf("Failed to decode authentication response: %v", err)
			}
			continue
		}

		var missing_fields []string
		if auth_response.AccessToken == "" {
			missing_fields = append(missing_fields, "access_token")
		}
		if auth_response.TokenType == "" {
			missing_fields = append(missing_fields, "token_type")
		}
		if auth_response.ExpiresIn <= 0 {
			missing_fields = append(missing_fields, "expires_in")
		}
		if len(missing_fields) > 0 {
			log.Printf("Authentication response is missing or has invalid required fields: %s", strings.Join(missing_fields, ", "))
			continue
		}

		access_token = auth_response.AccessToken
		token_type = auth_response.TokenType
		expires := auth_response.ExpiresIn - (60 * 5)
		token_refresh_time = time.Now().UTC().Add(time.Second * time.Duration(expires))

		log.Printf("Access token updated (type: %s, expires_in: %ds)", token_type, auth_response.ExpiresIn)
		log.Printf("Token refresh scheduled at %s", token_refresh_time)
		break
	}
}

// Go routine to handle token refresh on a loop
func handleTokenRefresh() {
	for {
		current_time := time.Now().UTC()
		if current_time.After(token_refresh_time) {
			log.Print("Refreshing access token")
			getOuath2AuthAccessToken()
		}
		time.Sleep(30 * time.Second)
	}
}

// Retrieves a named environment variable. validates that required
// variables are supplied, and supplies defaults for missing values
func getEnvironmentVariable(key string, required bool, secret bool, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		if secret {
			log.Printf("%s=**************", key)
		} else {
			log.Printf("%s=%s", key, value)
		}
		return value
	}

	if required {
		log.Fatalf("Environment variable %s must be supplied", key)
	}

	if fallback != "" {
		log.Printf("%s=%s (Default Value)", key, fallback)
	}
	return fallback
}

// Initialize variables from environment
func initVariables() {
	auth_endpoint_url = getEnvironmentVariable("AUTH_ENDPOINT_URL", true, false, "")
	auth_client_id = getEnvironmentVariable("AUTH_CLIENT_ID", true, true, "")
	auth_client_secret = getEnvironmentVariable("AUTH_CLIENT_SECRET", true, true, "")
	auth_scope = getEnvironmentVariable("AUTH_SCOPE", false, false, "")
	proxy_downstream_url = getEnvironmentVariable("PROXY_DOWNSTREAM_URL", true, false, "")
	proxy_downstream_wss = getEnvironmentVariable("PROXY_DOWNSTREAM_WSS", false, false, proxy_downstream_url)
	proxy_port = getEnvironmentVariable("PROXY_PORT", false, false, "10801")
	downstream_api_key = getEnvironmentVariable("DOWNSTREAM_API_KEY", false, true, "")
	downstream_api_key_header = strings.TrimSpace(getEnvironmentVariable("DOWNSTREAM_API_KEY_HEADER", false, false, "x-api-key"))
	if downstream_api_key_header == "" {
		log.Fatal("DOWNSTREAM_API_KEY_HEADER must not be empty")
	}
	if strings.EqualFold(downstream_api_key_header, "Authorization") {
		log.Fatal("DOWNSTREAM_API_KEY_HEADER must not be Authorization: it would overwrite the OAuth2 access token")
	}
	inbound_api_key = getEnvironmentVariable("INBOUND_API_KEY", true, true, "")
	if strings.TrimSpace(inbound_api_key) == "" {
		log.Fatal("INBOUND_API_KEY must not be empty")
	}
}

// Main program entrypoint
func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds)

	log.Print("Initializing proxy")

	debug_enabled = strings.EqualFold(getEnvironmentVariable("LOG_LEVEL", false, false, "debug"), "debug")

	initVariables()

	log.Print("Getting initial access token")
	getOuath2AuthAccessToken()

	if access_token == "" {
		log.Fatal("Failed to acquire initial access token - terminating")
	}

	log.Print("Starting access token refresh background routine")
	go handleTokenRefresh()

	listen_address := ":" + proxy_port
	http.HandleFunc("/", handleRequestAndRedirect)
	log.Printf("Listening to path / on %s", listen_address)
	if err := http.ListenAndServe(listen_address, nil); err != nil {
		panic(err)
	}
}
