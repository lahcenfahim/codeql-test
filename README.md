# codeql-test
codeql database create test-database --language=python --source-root=. --overwrite

dans queries : codeql pack install
==============================================================
codeql database analyze test-database queries/dangerous-pickle.ql --format=csv --output=pickle-results.csv

codeql database analyze test-database queries/hardcoded-password.ql --format=csv --output=password-results.csv

codeql database analyze test-database C:\\Users\\elfah\\Desktop\\projects\\codeql\\python\\ql\\src\\Security --format=csv --output=standard-security.csv
