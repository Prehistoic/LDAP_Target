grammar ldap;

axiom: s EOF;

s: filtre;

filtre: '(' filtrecomp ')';

filtrecomp: '&' filtre* | '|' filtre* | '!' filtre | item;

item: attr '=' something;

attr: 'cn' | 'dn' | 'ou' | 'objectclass' | TEXT;

something: '*' | '*' TEXT | TEXT '*' | '*' TEXT '*' | TEXT | NUMBER;

NUMBER: DIGIT+;
TEXT: CHAR+;

fragment DIGIT: [0-9] ;
fragment CHAR: [a-zA-Z] ;

