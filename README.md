### SEPCAT :: Static Exploitable PHP Code Analysis Tool v0.4 Alpha

SEPCAT is a simple PHP Static Code Analysis (SCA) tool written in Perl.
It could be used to quickly test a PHP project that you think may have some potential vulnerabilities.

#### WARNING

This is an alpha version. It is not recommended to use in a production environment yet. I'm sharing this code only for testing. There will be a lot of changes, before release of usable version.

#### Usage

```
vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -folder test_vuln_files/
```

#### Example

```
vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -file test_vuln_files/XSS_test.php

[SEPCAT] Static Exploitable PHP Code Analysis Tool
[+] Scanning file: test_vuln_files/XSS_test.php

Line 16: Cross-Site Scripting (XSS) in 'echo' via '$age'

- - - - - - - - - - - - - - - - - - - - - - - - - - -

vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -file test_vuln_files/XSS_test.php

[SEPCAT] Static Exploitable PHP Code Analysis Tool
[+] Scanning file: test_vuln_files/RFI_test.php

Line 13: PHP File Inclusion in 'include' via '$rfi'

- - - - - - - - - - - - - - - - - - - - - - - - - - -

vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -folder test_vuln_files/

[SEPCAT] Static Exploitable PHP Code Analysis Tool
[+] Scanning folder: test_vuln_files/

Line 16: Cross-Site Scripting (XSS) in 'echo' via '$age'
Line 32: PHP File Inclusion in 'include' via '$rfi'
```

#### TODO
1) php_tokenizer() is a bad idea, need to write a better PHP parser (maybe with Regexp::Grammars)

2) Storing all tokens to one @tokens array is a very bad. Scanning a single file is OK, but not for folders, need to figure out how to pass file names and create separate array for each file.

3) Need better sinks for checking of single vulnerabilities.

4) Whole logic is bad, need to rewrite all parts of this crappy code.