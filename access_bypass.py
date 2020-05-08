#!/usr/bin/env python

import sys
import ldap
import ldap.modlist as modlist

def attempt_connect(searchFilter,connect,domain_name,domain_code):
    baseDN = "dc="+domain_name+", dc="+domain_code
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    result_set = []
    try:
    	ldap_result_id = connect.search(baseDN, searchScope, searchFilter, retrieveAttributes)
    	while 1:
    		result_type, result_data = connect.result(ldap_result_id, 0)
    		if (result_data == []):
    			break
    		else:
    			if result_type == ldap.RES_SEARCH_ENTRY:
    				result_set.append(result_data)
        result = 0
    except ldap.LDAPError, e:
    	result = 180
    print("")
    if result_set == []:
        print("ERROR ! Access denied !")
    else:
        print("WELCOME ! Acces granted !")
    print("")
    return result

def main(user_server,domain,user_login,user_password,injection):

    # little explanation of the tool
    print("Welcome to this access bypass training tool !")
    print("The expected credentials are : login=Bob and password=hardtoguess")
    print("We are looking for a way to gain access to the system without knowing the password !")
    print("Try using these credentials to witness an AND LDAP injection vulnerability : ")
    print("  -  login=* and password=*)(&")
    print("")

    server = user_server
    connect = ldap.initialize(server)
    domain_list = domain.split(".")
    domain_name = domain_list[0]
    domain_code = domain_list[1]
    login_credentials = "cn=" + user_login + ",dc=" + domain_name + ",dc=" + domain_code
    connect.simple_bind_s(login_credentials,user_password)

    # first we add the login information of a test user
    dn="cn=user1,dc="+domain_name+",dc="+domain_code
    attrs = {}
    attrs['objectclass'] = ['person']
    attrs['cn'] = 'user1'
    attrs['sn'] = 'Bob'
    attrs['description'] = 'hardtoguess'
    ldif = modlist.addModlist(attrs)
    connect.add_s(dn,ldif)

    connect.unbind_s()

    login = "Bob"
    password = injection

    # then we try to find a match in the LDAP DIT
    connect = ldap.initialize(server)

    # We escape if password = *
    if(password == '*'):
	password = '\\*'
    searchFilter = "(&(sn="+login+")(description="+password+"))"
    print("Filter used : "+searchFilter)
    result = attempt_connect(searchFilter,connect,domain_name,domain_code)

    # we clear the LDAP database for future use !
    connect.simple_bind_s("cn=admin,dc="+domain_name+",dc="+domain_code,user_password)
    deleteDN = "cn=user1, dc="+domain_name+", dc="+domain_code
    try:
    	connect.delete_s(deleteDN)
    except ldap.LDAPError, e:
    	print e
    connect.unbind_s()
    exit(result)

if __name__ == "__main__":
    if(len(sys.argv) == 6):
        main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])
    else:
        print("Usage: python access_bypass.py [server] [domain] [domain_login] [domain_password] [injection]")
