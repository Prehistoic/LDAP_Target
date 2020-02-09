#!/usr/bin/env python

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
    except ldap.LDAPError, e:
    	pass
    print("")
    if result_set == []:
        print("ERROR ! Access denied !")
    else:
        print("WELCOME ! Acces granted !")
    print("")

# little explanation of the tool
print("Welcome to this access bypass training tool !")
print("The expected credentials are : login=Bob and password=easytoguess")
print("However there is another way to gain access to the system without knowing the password !")
print("Try using these credentials to witness AND LDAP injection vulnerabilities : ")
print("  -  login=* and password=*")
print("  -  login=Bob)(|(cn=* and password=123)")
print("  -  login=Bob)(|(& and password=123)")
print("")

server = 'ldap://localhost:389'
connect = ldap.initialize(server)
connect.simple_bind_s("cn=admin,dc=vuln,dc=com","secret")

# first we add the login informations of a test user
dn="cn=user1,dc=vuln,dc=com"
attrs = {}
attrs['objectclass'] = ['person']
attrs['cn'] = 'user1'
attrs['sn'] = 'Bob'
attrs['description'] = 'easytoguess'
ldif = modlist.addModlist(attrs)
connect.add_s(dn,ldif)

connect.unbind_s()

# we ask the user to login
login = raw_input("Login :\n")
password = raw_input("Password :\n")

# then we try to find a match in the LDAP DIT
connect = ldap.initialize(server)

# Case 1 : No protection
print("=====================================================")
print("")
print("Case 1 : No protection")
searchFilter = "(&(sn="+login+")(description="+password+"))"
print("Filter used : "+searchFilter)
attempt_connect(searchFilter,connect)

# Case 2 : Escaping entries equals to *
print("=====================================================")
print("")
print("Case 2 : Escaping entries equals to *")
safelogin=login
safepassword=password
if(safelogin=='*'):
    safelogin='\\*'
if(safepassword=='*'):
    safepassword='\\*'
searchFilter = "(&(sn="+safelogin+")(description="+safepassword+"))"
print("Filter used : "+searchFilter)
attempt_connect(searchFilter,connect)

# Case 3 : Escaping all * characters
print("=====================================================")
print("")
print("Case 3 : Escaping all * characters")
safelogin = login.replace('*','\\*')
safepassword = password.replace('*','\\*')
searchFilter = "(&(sn="+safelogin+")(description="+safepassword+"))"
print("Filter used : "+searchFilter)
attempt_connect(searchFilter,connect)

# Case 4 : Escaping all dangerous characters
print("=====================================================")
print("")
print("Case 4 : Escaping all dangerous characters")
safelogin = login.replace('*','\\*').replace('&','\&').replace('|','\|')
safepassword = password.replace('*','\\*').replace('&','\&').replace('|','\|')
searchFilter = "(&(sn="+safelogin+")(description="+safepassword+"))"
print("Filter used : "+searchFilter)
attempt_connect(searchFilter,connect)

# we clear the LDAP database for future use !
connect.simple_bind_s("cn=admin,dc=vuln,dc=com","secret")
deleteDN = "cn=user1, dc=vuln, dc=com"
try:
	connect.delete_s(deleteDN)
except ldap.LDAPError, e:
	print e
connect.unbind_s()
