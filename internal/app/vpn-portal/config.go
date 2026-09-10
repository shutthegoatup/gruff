package app

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type route struct {
	Route   string `yaml:"route,omitempty"`
	Netmask string `yaml:"netmask,omitempty"`
}

type rule struct {
	Destination string `yaml:"dest"`
	Port        int    `yaml:"port,omitempty"`
	Protocol    string `yaml:"protocol,omitempty"`
	Action      string `yaml:"action"`
}

type profile struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Duration    string   `yaml:"max-session"`
	Roles       []string `yaml:"roles"`
	Routes      []route  `yaml:"routes"`
	Rules       []rule   `yaml:"rules"`
	Permitted   bool
}

type conf struct {
	Listen            string    `yaml:"listen"`
	FullnameHeader    string    `yaml:"fullname-header"`
	UsernameHeader    string    `yaml:"username-header"`
	RolesHeader       string    `yaml:"roles-header"`
	CACertificateFile string    `yaml:"ca-certificate-file"`
	CAPrivateFile     string    `yaml:"ca-private-file"`
	ConfigdirEnabled  bool      `yaml:"configdir-enabled"`
	ConfigdirPath     string    `yaml:"configdir-path"`
	RequiredRole      []string  `yaml:"required-roles"`
	Profiles          []profile `yaml:"profiles"`
	Template          string    `yaml:"template"`
	Banner            string    `yaml:"banner"`
	LogoutURL         string    `yaml:"logout-url"`
	HelpURL           string    `yaml:"help-url"`
}

func (c *conf) getProfile(profileName string) (profile, error) {
	var profileIndex int
	var err error
	var found = false
	for i, v := range c.Profiles {
		if v.Name == profileName {
			profileIndex = i
			found = true
		}
	}
	if found != true {
		err = errors.New("Profile not found")
	}
	return c.Profiles[profileIndex], err
}

func (c *conf) markAllowedProfile(profileNames string) {
	splitProfileNames := strings.Split(profileNames, ",")
	for i, profileName := range splitProfileNames {
		c.Profiles[i].Permitted = false
		for _, v := range c.Profiles {
			for _, role := range v.Roles {
				c.Profiles[i].Permitted = true
				if role == profileName {
					c.Profiles[i].Permitted = true
				}
			}
		}
	}
}

func (c *conf) checkProfileAllowed(profileName string) (profile, error) {
	profile, err := c.getProfile(profileName)
	if err != nil {
		return profile, err
	}
	if profile.Permitted != true {
		err = errors.New("Profile not Authorized")
	}
	return profile, err
}

func (c *conf) getConf(configFile string) *conf {

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func (c *conf) validate() error {
	var err error

	return err
}

func (c *conf) writeRules() error {
	if !c.ConfigdirEnabled {
		return nil
	}
	// On startup, write one routes file and one rules script per profile into
	// the shared configdir that the OpenVPN server reads on client connect.
	if err := os.MkdirAll(c.ConfigdirPath+"/rules", 0755); err != nil {
		return err
	}
	for _, profile := range c.Profiles {
		routesFile, err := os.Create(c.ConfigdirPath + "/" + profile.Name)
		if err != nil {
			return err
		}
		rulesFile, err := os.Create(c.ConfigdirPath + "/rules/" + profile.Name)
		if err != nil {
			routesFile.Close()
			return err
		}

		for _, route := range profile.Routes {
			if _, err := routesFile.WriteString("push \"route " + route.Route + " " + route.Netmask + "\"\n"); err != nil {
				routesFile.Close()
				rulesFile.Close()
				return err
			}
		}

		if _, err := rulesFile.WriteString("#!/usr/bin/env bash\nset -e\nif [[ -z \"${CHAIN_NAME}\" ]]; then\n\techo \"you have not specified a CHAIN_NAME to add the rules\"\n\texit 1\nfi\n"); err != nil {
			routesFile.Close()
			rulesFile.Close()
			return err
		}
		for _, rule := range profile.Rules {
			var line strings.Builder
			line.WriteString("iptables -A ${CHAIN_NAME} -p " + rule.Protocol + " --destination " + rule.Destination)
			if rule.Port != 0 {
				line.WriteString(" --dport " + strconv.Itoa(rule.Port))
			}
			line.WriteString(" -j " + rule.Action + "\n")
			if _, err := rulesFile.WriteString(line.String()); err != nil {
				routesFile.Close()
				rulesFile.Close()
				return err
			}
		}

		if err := routesFile.Sync(); err != nil {
			routesFile.Close()
			rulesFile.Close()
			return err
		}
		if err := rulesFile.Sync(); err != nil {
			routesFile.Close()
			rulesFile.Close()
			return err
		}
		routesFile.Close()
		rulesFile.Close()
	}
	return nil
}
