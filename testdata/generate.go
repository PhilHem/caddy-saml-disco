//go:build ignore

// This program generates large metadata aggregate fixtures for performance testing.
// Run with: go run testdata/generate.go -count 1000 -output testdata/large-metadata.xml
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

var metadataTemplate = template.Must(template.New("metadata").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
                    xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
                    validUntil="{{.ValidUntil}}">
{{range .IdPs}}
    <EntityDescriptor entityID="{{.EntityID}}">
        <Extensions>
            <mdrpi:RegistrationInfo registrationAuthority="{{.RegistrationAuthority}}"
                                    registrationInstant="{{.RegistrationInstant}}"/>
        </Extensions>
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <Extensions>
                <mdui:UIInfo>
                    <mdui:DisplayName xml:lang="en">{{.DisplayNameEN}}</mdui:DisplayName>
                    <mdui:DisplayName xml:lang="de">{{.DisplayNameDE}}</mdui:DisplayName>
                    <mdui:Description xml:lang="en">{{.DescriptionEN}}</mdui:Description>
                    <mdui:Logo height="64" width="64">{{.LogoURL}}</mdui:Logo>
                    <mdui:InformationURL xml:lang="en">{{.InfoURL}}</mdui:InformationURL>
                </mdui:UIInfo>
            </Extensions>
            <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>{{.Certificate}}</X509Certificate>
                    </X509Data>
                </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="{{.SSOURL}}"/>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="{{.SSOURLPost}}"/>
        </IDPSSODescriptor>
        <Organization>
            <OrganizationName xml:lang="en">{{.OrgName}}</OrganizationName>
            <OrganizationDisplayName xml:lang="en">{{.DisplayNameEN}}</OrganizationDisplayName>
            <OrganizationURL xml:lang="en">{{.OrgURL}}</OrganizationURL>
        </Organization>
    </EntityDescriptor>
{{end}}
</EntitiesDescriptor>
`))

type IdPData struct {
	EntityID              string
	DisplayNameEN         string
	DisplayNameDE         string
	DescriptionEN         string
	LogoURL               string
	InfoURL               string
	SSOURL                string
	SSOURLPost            string
	OrgName               string
	OrgURL                string
	Certificate           string
	RegistrationAuthority string
	RegistrationInstant   string
}

type TemplateData struct {
	ValidUntil string
	IdPs       []IdPData
}

// Sample organization types for variety
var orgTypes = []string{
	"University", "College", "Institute", "Academy", "School",
	"Research Center", "Laboratory", "Foundation", "Hospital", "Library",
}

// Sample countries for variety
var countries = []string{
	"us", "uk", "de", "fr", "nl", "be", "ch", "at", "it", "es",
	"pl", "cz", "se", "no", "dk", "fi", "ie", "pt", "gr", "hu",
}

// Sample federations
var federations = []string{
	"https://incommon.org",
	"https://www.aai.dfn.de",
	"https://www.ukfederation.org.uk",
	"https://federation.renater.fr",
	"https://www.surfconext.nl",
}

// Fake certificate (realistic length, ~1KB base64)
var fakeCert = strings.Repeat("MIICpDCCAYwCCQDU+pQ4P2dP3jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls", 20)

func main() {
	count := flag.Int("count", 100, "Number of IdPs to generate")
	output := flag.String("output", "", "Output file (stdout if empty)")
	flag.Parse()

	data := TemplateData{
		ValidUntil: "2099-12-31T23:59:59Z",
		IdPs:       make([]IdPData, *count),
	}

	for i := 0; i < *count; i++ {
		country := countries[i%len(countries)]
		orgType := orgTypes[i%len(orgTypes)]
		federation := federations[i%len(federations)]

		data.IdPs[i] = IdPData{
			EntityID:              fmt.Sprintf("https://idp%04d.%s.example.edu/saml", i, country),
			DisplayNameEN:         fmt.Sprintf("%s of %s %04d", orgType, strings.ToUpper(country), i),
			DisplayNameDE:         fmt.Sprintf("%s von %s %04d", orgType, strings.ToUpper(country), i),
			DescriptionEN:         fmt.Sprintf("Identity Provider for %s of %s, serving students and staff.", orgType, strings.ToUpper(country)),
			LogoURL:               fmt.Sprintf("https://idp%04d.%s.example.edu/logo.png", i, country),
			InfoURL:               fmt.Sprintf("https://idp%04d.%s.example.edu/info", i, country),
			SSOURL:                fmt.Sprintf("https://idp%04d.%s.example.edu/sso/redirect", i, country),
			SSOURLPost:            fmt.Sprintf("https://idp%04d.%s.example.edu/sso/post", i, country),
			OrgName:               fmt.Sprintf("%s of %s", orgType, strings.ToUpper(country)),
			OrgURL:                fmt.Sprintf("https://www.%s%04d.example.edu", country, i),
			Certificate:           base64.StdEncoding.EncodeToString([]byte(fakeCert + fmt.Sprintf("%04d", i))),
			RegistrationAuthority: federation,
			RegistrationInstant:   "2020-01-15T10:30:00Z",
		}
	}

	var out *os.File
	if *output == "" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	}

	if err := metadataTemplate.Execute(out, data); err != nil {
		fmt.Fprintf(os.Stderr, "failed to execute template: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		fmt.Fprintf(os.Stderr, "Generated %d IdPs to %s\n", *count, *output)
	}
}
