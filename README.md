### SEPCAT :: Static Exploitable PHP Code Analysis Tool v0.3

SEPCAT is a simple PHP Static Code Analysis (SCA) tool written in Perl.
It could be used to quickly test a PHP project that you think may have some potential vulnerabilities. 

#### Usage

```
vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -folder /var/www/sepcat-test/
```

#### Example

```
File: /var/www/sepcat-test/index.php
Line 7: Cross-Site Scripting found in 'echo' via '$name'
Vuln code:
echo('Hello ' . $name); # tainted data reaches sensitive sink

File: /var/www/sepcat-test/index.php
Line 11: SQL Injection found in 'mysql_query' via '$id'
Vuln code:
mysql_query("SELECT user FROM users WHERE id = " . $id);

File: /var/www/sepcat-test/index.php
Line 15: Command Injection found in 'exec' via '$cmd'
Vuln code:
exec("cat /var/log/apache2/access.log | grep " . $cmd);

File: /var/www/sepcat-test/index.php
Line 21: PHP File Inclusion found in 'include' via '$_GET'
Vuln code:
include $_GET['rfi'].".html";
```