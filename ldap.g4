grammar ldap;

axiom: s EOF;

s: filter;

filter: '(' filtercomp ')';

filtercomp: 
  '&' filter filter
  | '|' filter filter
  | '!' filter
  | item
  ;

item: attr '=' something;

attr: 'cn' | 'dn' | 'ou' | 'objectClass' | TEXT;

something: '*' | '*' TEXT | TEXT '*' | '*' TEXT '*' | NUMBER;

NUMBER: DIGIT+;
TEXT: CHAR+;

fragment DIGIT: [0-9] ;
fragment CHAR: [a-zA-Z] ;

