package sa_auth

import (
	"errors"
	"fmt"
	"github.com/mavricknz/ldap"
	//"reflect"
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

//login check, input account, domain, passwd, server, port and base_dn for search
func SaAuthCheck(
	account,
	passwd,
	domain,
	ldap_server string,
	ldap_port uint16,
	base_dn string,
) UserAuth {

	user := UserAuth{Login: false, HasThumb: false}
	var err error

	//connect
	var l *ldap.LDAPConnection
	l = ldap.NewLDAPConnection(ldap_server, ldap_port)
	err = l.Connect()
	if err != nil {
		user.Err = err
		return user
	}
	defer l.Close()

	//blank pasword is not acceptable
	if passwd == "" {
		err := errors.New("Please fill in password!")
		user.Err = err
		return user
	}
	//authentification (Bind)
	loginname := account + "@" + domain
	err = l.Bind(loginname, passwd)
	if err != nil {
		// err = errors.New("Wrong password or account.")
		user.Err = err
		return user
	}
	user.Login = true

	//Search, Get entries and Save entry
	attributes := []string{}
	filter := fmt.Sprintf(
		"(&(objectclass=user)(samaccountname=%s))",
		account,
	)
	search_request := ldap.NewSimpleSearchRequest(
		base_dn,
		2, //ScopeWholeSubtree 2, ScopeSingleLevel 1, ScopeBaseObject 0 ??
		filter,
		attributes,
	)
	sr, _ := l.Search(search_request)
	user.Account = account
	user.Name = sr.Entries[0].GetAttributeValue("name")
	user.Mail = sr.Entries[0].GetAttributeValue("mail")
	user.Thumb = sr.Entries[0].GetAttributeValue("thumbnailphoto")
	if user.Thumb != "" {
		user.HasThumb = true
	}

	return user
}
