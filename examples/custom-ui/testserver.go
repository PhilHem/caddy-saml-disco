// +build ignore

// testserver.go - A mock API server for testing the custom UI
// Run with: go run testserver.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type IdP struct {
	EntityID    string `json:"entity_id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
}

type Session struct {
	Authenticated bool              `json:"authenticated"`
	User          string            `json:"user,omitempty"`
	IdP           string            `json:"idp,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

var idps = []IdP{
	{EntityID: "https://idp.university.edu", DisplayName: "University of Example", Description: "Main university IdP"},
	{EntityID: "https://sso.college.edu", DisplayName: "Example College", Description: "Community college SSO"},
	{EntityID: "https://login.research.org", DisplayName: "Research Institute", Description: "National research network"},
	{EntityID: "https://idp.hospital.org", DisplayName: "Central Hospital", Description: "Healthcare provider"},
	{EntityID: "https://sso.library.net", DisplayName: "Public Library System", Description: "Library consortium"},
	{EntityID: "https://auth.startup.io", DisplayName: "Startup Inc", Description: "Tech startup"},
	{EntityID: "https://login.nonprofit.org", DisplayName: "Nonprofit Foundation", Description: "Charitable organization"},
	{EntityID: "https://idp.government.gov", DisplayName: "Government Agency", Description: "Federal identity provider"},
}

var session = Session{Authenticated: false}

func main() {
	// Serve static files
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	// API endpoints
	http.HandleFunc("/saml/api/idps", handleIdPs)
	http.HandleFunc("/saml/api/select", handleSelect)
	http.HandleFunc("/saml/api/session", handleSession)
	http.HandleFunc("/saml/logout", handleLogout)

	fmt.Println("Test server running at http://localhost:8765")
	fmt.Println("Custom UI: http://localhost:8765/login.html")
	fmt.Println("\nAvailable endpoints:")
	fmt.Println("  GET  /saml/api/idps     - List IdPs")
	fmt.Println("  POST /saml/api/select   - Select IdP (simulates login)")
	fmt.Println("  GET  /saml/api/session  - Check session")
	fmt.Println("  GET  /saml/logout       - Logout")
	log.Fatal(http.ListenAndServe(":8765", nil))
}

func handleIdPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	query := strings.ToLower(r.URL.Query().Get("q"))
	var filtered []IdP

	for _, idp := range idps {
		if query == "" ||
			strings.Contains(strings.ToLower(idp.DisplayName), query) ||
			strings.Contains(strings.ToLower(idp.Description), query) ||
			strings.Contains(strings.ToLower(idp.EntityID), query) {
			filtered = append(filtered, idp)
		}
	}

	// Check for remembered_idp cookie
	var rememberedIdPID string
	if cookie, err := r.Cookie("remembered_idp"); err == nil {
		rememberedIdPID = cookie.Value
	}

	// Return in expected format: { idps: [...], remembered_idp_id: "..." }
	json.NewEncoder(w).Encode(map[string]interface{}{
		"idps":             filtered,
		"remembered_idp_id": rememberedIdPID,
	})
}

func handleSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EntityID  string `json:"entity_id"`
		ReturnURL string `json:"return_url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Find the IdP
	var selectedIdP *IdP
	for _, idp := range idps {
		if idp.EntityID == req.EntityID {
			selectedIdP = &idp
			break
		}
	}

	if selectedIdP == nil {
		http.Error(w, "IdP not found", http.StatusNotFound)
		return
	}

	// Simulate successful login
	session = Session{
		Authenticated: true,
		User:          "testuser@example.com",
		IdP:           selectedIdP.DisplayName,
		Attributes: map[string]string{
			"email":     "testuser@example.com",
			"name":      "Test User",
			"entity_id": req.EntityID,
		},
	}

	// Set a cookie to remember the IdP
	http.SetCookie(w, &http.Cookie{
		Name:   "remembered_idp",
		Value:  req.EntityID,
		Path:   "/",
		MaxAge: 86400 * 30, // 30 days
	})

	returnURL := req.ReturnURL
	if returnURL == "" {
		returnURL = "/"
	}

	// Return HTTP redirect (like the real SAML SP does)
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(session)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session = Session{Authenticated: false}

	// Check if this is an API call or browser redirect
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
	} else {
		http.Redirect(w, r, "/login.html", http.StatusFound)
	}
}
