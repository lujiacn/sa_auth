package saauth

import (
	"errors"
	"fmt"

	"crypto/tls"

	"github.com/mavricknz/ldap"
)

type Auth struct {
	IsLoggedIn bool
	HasThumb   bool
	SAMAccount string
	Mail       string
	First      string
	Last       string
	Depart     string
	Thumb      string
	Name       string
	Err        error
}

type saLdap struct {
	ldapServer     string
	ldapPort       uint16
	ldapSSL        bool
	baseDn         string
	bindUserName   string
	bindUserPasswd string
	ldap           *ldap.LDAPConnection
	tlsConfig      *tls.Config
}

func NewSaLdap(ldapServer string, ldapPort uint16,
	ldapSSL bool,
	baseDn string, userName, userPasswd string, tlsConfig *tls.Config) *saLdap {
	sa := &saLdap{ldapServer: ldapServer, ldapPort: ldapPort, ldapSSL: ldapSSL,
		baseDn: baseDn, bindUserName: userName, bindUserPasswd: userPasswd, tlsConfig: tlsConfig}
	return sa
}

func (s *saLdap) connect() error {
	if s.ldapSSL {
		if s.tlsConfig == nil {
			s.ldap = ldap.NewLDAPSSLConnection(s.ldapServer, s.ldapPort, &tls.Config{InsecureSkipVerify: true})
		} else {
			s.ldap = ldap.NewLDAPSSLConnection(s.ldapServer, s.ldapPort, s.tlsConfig)
		}
		err := s.ldap.Connect()
		if err != nil {
			return err
		}
	} else {
		s.ldap = ldap.NewLDAPConnection(s.ldapServer, s.ldapPort)
		err := s.ldap.Connect()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *saLdap) Authenticate(account, passwd, domain string) *Auth {
	defer func() {
		if s.ldap != nil {
			s.ldap.Close()
		}
	}()

	//Default
	auth := &Auth{IsLoggedIn: false, HasThumb: false}
	err := s.connect()

	if err != nil {
		auth.Err = err
		return auth
	}

	//authentification (Bind)
	loginname := fmt.Sprintf(`%s\%s`, domain, account)
	err = s.ldap.Bind(loginname, passwd)

	if err != nil {
		auth.Err = errors.New("Invalid account or password.")
		return auth
	}

	auth.IsLoggedIn = true

	//bind Admin user for query
	err = s.ldap.Bind(s.bindUserName, s.bindUserPasswd)
	if err != nil {
		auth.Err = errors.New("Cannot query user information due to limited privilege.")
		return auth
	}

	//Search, Get entries and Save entry
	attributes := []string{}
	filter := fmt.Sprintf(
		"(&(objectclass=user)(samaccountname=%s))",
		account,
	)
	search_request := ldap.NewSimpleSearchRequest(
		s.baseDn,
		2, //ScopeWholeSubtree 2, ScopeSingleLevel 1, ScopeBaseObject 0 ??
		filter,
		attributes,
	)
	sr, err := s.ldap.Search(search_request)
	if err != nil {
		auth.Err = err
		return auth
	}
	auth.SAMAccount = account
	auth.Name = sr.Entries[0].GetAttributeValue("name")
	auth.Mail = sr.Entries[0].GetAttributeValue("mail")
	auth.Thumb = sr.Entries[0].GetAttributeValue("thumbnailphoto")
	auth.Last = sr.Entries[0].GetAttributeValue("givenname")
	auth.First = sr.Entries[0].GetAttributeValue("sn")
	auth.Depart = sr.Entries[0].GetAttributeValue("department")
	if auth.Thumb != "" {
		auth.HasThumb = true
	}

	return auth
}

//GetUser only search account name and email
func (s *saLdap) QueryUser(account string) *Auth {
	defer func() {
		if s.ldap != nil {
			s.ldap.Close()
		}
	}()

	auth := &Auth{IsLoggedIn: false, HasThumb: false}
	err := s.connect()
	if err != nil {
		auth.Err = err
		return auth
	}

	//bind Admin user for query
	err = s.ldap.Bind(s.bindUserName, s.bindUserPasswd)
	if err != nil {
		auth.Err = errors.New("Cannot query user information due to limited privilege.")
		return auth
	}

	//Search, Get entries and Save entry
	attributes := []string{}
	filter := fmt.Sprintf(
		"(&(objectclass=user)(samaccountname=%s))",
		account,
	)
	search_request := ldap.NewSimpleSearchRequest(
		s.baseDn,
		2, //ScopeWholeSubtree 2, ScopeSingleLevel 1, ScopeBaseObject 0 ??
		filter,
		attributes,
	)
	sr, err := s.ldap.Search(search_request)
	if err != nil {
		auth.Err = err
		return auth
	}
	if len(sr.Entries) == 0 {
		auth.Err = errors.New(fmt.Sprintf("Account %s not exist!", account))
		return auth
	}
	auth.SAMAccount = account
	auth.Name = sr.Entries[0].GetAttributeValue("name")
	auth.Mail = sr.Entries[0].GetAttributeValue("mail")
	auth.Thumb = sr.Entries[0].GetAttributeValue("thumbnailphoto")
	auth.Last = sr.Entries[0].GetAttributeValue("givenname")
	auth.First = sr.Entries[0].GetAttributeValue("sn")
	auth.Depart = sr.Entries[0].GetAttributeValue("department")
	if auth.Thumb != "" {
		auth.HasThumb = true
	}

	return auth
}
