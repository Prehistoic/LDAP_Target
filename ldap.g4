grammar ldap;

axiom: s EOF;

s: '(' filtercomp s ')' |  ;

filtercomp: '&' | '|' | '!' | item;

item: attr filtertype something;

attr: 'cn' | 'dn' | 'ou' | 'objectClass' | TEXT;

filtertype: '=';

something: '*' | '*' TEXT | TEXT '*' | '*' TEXT '*' | NUMBER;

NUMBER: DIGIT+;
TEXT: CHAR+;

fragment DIGIT: [0-9] ;
fragment CHAR: [a-zA-Z] ;

