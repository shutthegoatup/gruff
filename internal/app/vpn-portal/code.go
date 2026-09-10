package app

import (
	"fmt"
	"github.com/gorilla/mux"
	"html/template"
	"net/http"
	texttemplate "text/template"
	"time"
)

func issuedHandler(w http.ResponseWriter, r *http.Request) {
	type webData struct {
		Profiles  []session
		Title     string
		Brand     string
		Username  string
		LogoutURL string
		HelpURL   string
	}
	wd := webData{
		Profiles:  s.ForUser(r.Header.Get(c.UsernameHeader)),
		Title:     c.Banner,
		Brand:     c.Banner,
		Username:  r.Header.Get(c.FullnameHeader),
		LogoutURL: c.LogoutURL,
		HelpURL:   c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"web/template/layout.html",
		"web/template/issued.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile, _ := c.getProfile(vars["profile"])
	type webData struct {
		Title       string
		Brand       string
		Username    string
		LogoutURL   string
		Description string
		Rules       []rule
		Routes      []route
		Roles       []string
		HelpURL     string
	}

	wd := webData{
		Title:       c.Banner,
		Brand:       c.Banner,
		Username:    r.Header.Get(c.FullnameHeader),
		LogoutURL:   c.LogoutURL,
		Description: profile.Description,
		Rules:       profile.Rules,
		Routes:      profile.Routes,
		Roles:       profile.Roles,
		HelpURL:     c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"web/template/layout.html",
		"web/template/rules.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	c.markAllowedProfile(r.Header.Get(c.RolesHeader))
	vars := mux.Vars(r)
	profile, err := c.checkProfileAllowed(vars["profile"])
	if err != nil {
		http.Error(w, "Not authorized", 401)
		return
	}

	requestIP := r.RemoteAddr
	issueTime := time.Now()
	durationTime, _ := time.ParseDuration(profile.Duration)
	expireTime := issueTime.Add(durationTime)

	k, err := ca.GenerateCertificate(issueTime, expireTime, vars["profile"])
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	mySession := session{
		IssuedOn:    issueTime.String(),
		User:        r.Header.Get(c.UsernameHeader),
		Profile:     profile.Name,
		ExpiresOn:   expireTime.String(),
		ClientIP:    requestIP,
		IssuingCA:   k.IssuingCA,
		Certificate: k.PublicKey,
		PrivateKey:  k.PrivateKey,
		Duration:    durationTime.String(),
	}

	type webData struct {
		Session session
	}
	wd := webData{
		Session: mySession,
	}

	s.AddItem(mySession)
	filename := vars["profile"] + "-" + expireTime.String() + ".ovpn"

	tmpl := texttemplate.Must(texttemplate.New(filename).Parse(c.Template))
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	err = tmpl.Execute(w, &wd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func profilesHandler(w http.ResponseWriter, r *http.Request) {
	c.markAllowedProfile(r.Header.Get(c.RolesHeader))

	type webData struct {
		Profiles  []profile
		Title     string
		Username  string
		Brand     string
		LogoutURL string
		HelpURL   string
	}
	wd := webData{
		Profiles:  c.Profiles,
		Title:     c.Banner,
		Username:  r.Header.Get(c.FullnameHeader),
		Brand:     c.Banner,
		LogoutURL: c.LogoutURL,
		HelpURL:   c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"web/template/layout.html",
		"web/template/profiles.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
