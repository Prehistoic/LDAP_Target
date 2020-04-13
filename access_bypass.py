#!/usr/bin/env python

import sys
import ldap
import ldap.modlist as modlist

def attempt_connect(searchFilter,connect):
    baseDN = "dc=vuln, dc=com"
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

def main(argv):

    # little explanation of the tool
    print("Welcome to this access bypass training tool !")
    print("The expected credentials are : login=Bob and password=hardtoguess")
    print("We are looking for a way to gain access to the system without knowing the password !")
    print("Try using these credentials to witness an AND LDAP injection vulnerability : ")
    print("  -  login=* and password=*)(&")
    print("")

    server = 'ldap://localhost:389'
    connect = ldap.initialize(server)
    connect.simple_bind_s("cn=admin,dc=vuln,dc=com","secret")

    # first we add the login information of a test user
    dn="cn=user1,dc=vuln,dc=com"
    attrs = {}
    attrs['objectclass'] = ['person']
    attrs['cn'] = 'user1'
    attrs['sn'] = 'Bob'
    attrs['description'] = 'hardtoguess'
    ldif = modlist.addModlist(attrs)
    connect.add_s(dn,ldif)

    connect.unbind_s()

    login = "*"
    password = argv

    # then we try to find a match in the LDAP DIT
    connect = ldap.initialize(server)

    # We escape if password = *
    if(password == '*'):
	password = '\\*'
    searchFilter = "(&(sn="+login+")(description="+password+"))"
    print("Filter used : "+searchFilter)
    result = attempt_connect(searchFilter,connect)

    # we clear the LDAP database for future use !
    connect.simple_bind_s("cn=admin,dc=vuln,dc=com","secret")
    deleteDN = "cn=user1, dc=vuln, dc=com"
    try:
    	connect.delete_s(deleteDN)
    except ldap.LDAPError, e:
    	print e
    connect.unbind_s()
    exit(result)

if __name__ == "__main__":
    main(sys.argv[1])
