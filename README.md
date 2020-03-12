# Access bypass testing tool : AND LDAP injections

## Getting started

### Prerequisites

- Having Python2 installed (version used to test this tool: Python 2.7)
- Using a Linux-based OS
- Having slapd installed

### Installing slapd

- sudo apt-get install slapd
- sudo dpkg-reconfigure slapd

1. Pass OpenLDAP configuration ? no
2. Domain name ? vuln.com
3. Company name ? vuln
4. Which database ? hdb
5. Do you want the database to be deleted when slapd is purged ? yes
6. Delete old databases ? yes
7. Admin password ? secret
8. Confirm password ? secret
9. Authorize LDAPv2 protocol ? no

- edit /etc/ldap/ldap.conf with admin rights (or create it if need be)

ldap_version 3 <br />
URI ldap://localhost:389 <br />
SIZELIMIT 0 <br />
TIMELIMIT 0 <br />
DEREF never <br />
BASE dc=vuln, dc=com

## Running the tool

To run the tool, open a terminal, go to the root directory of the git repository and use the command :

./oracle_ldap.sh <injection>
