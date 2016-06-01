package sa_auth

import (
	"errors"
	"fmt"
	"github.com/mavricknz/ldap"
	// "github.com/go-ldap/ldap"
	//"reflect"
	"crypto/tls"
)

type UserAuth struct {
	Login    bool
	HasThumb bool
	Account  string
	Mail     string
	Thumb    string
	Name     string
	Err      error
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

func (s *saLdap) AuthUser(account, passwd, domain string) UserAuth {
	if s.ldap != nil {
		defer s.ldap.Close()
	}
	user := UserAuth{Login: false, HasThumb: false}
	err := s.connect()
	if err != nil {
		fmt.Println("connection error")
		user.Err = err
		return user
	}
	//authentification (Bind)
	loginname := fmt.Sprintf(`%s\%s`, domain, account)
	err = s.ldap.Bind(loginname, passwd)
	if err != nil {
		fmt.Println("Wrong password or account.")
		user.Err = err
		return user
	}
	user.Login = true

	//bind Admin user for query
	err = s.ldap.Bind(s.bindUserName, s.bindUserPasswd)
	if err != nil {
		user.Err = errors.New("Cannot query user information.")
		return user
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
	sr, _ := s.ldap.Search(search_request)
	user.Account = account
	user.Name = sr.Entries[0].GetAttributeValue("name")
	user.Mail = sr.Entries[0].GetAttributeValue("mail")
	user.Thumb = sr.Entries[0].GetAttributeValue("thumbnailphoto")
	if user.Thumb != "" {
		user.HasThumb = true
	}

	return user
}

//GetUser only search account name and email
func (s *saLdap) GetUser(account string) UserAuth {
	if s.ldap != nil {
		defer s.ldap.Close()
	}
	user := UserAuth{Login: false, HasThumb: false}
	err := s.connect()
	if err != nil {
		fmt.Println("connection error")
		user.Err = err
		return user
	}

	//bind Admin user for query
	err = s.ldap.Bind(s.bindUserName, s.bindUserPasswd)
	if err != nil {
		user.Err = errors.New("Cannot query user infoormation.")
		return user
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
		user.Err = err
		return user
	}
	user.Account = account
	if sr != nil && len(sr.Entries) > 0 {
		user.Name = sr.Entries[0].GetAttributeValue("name")
		user.Mail = sr.Entries[0].GetAttributeValue("mail")
	}
	return user
}
