# Improper Assets Management

## Check List

## Methodology

### Black Box

#### Deprecated API Version Exposed

{% stepper %}
{% step %}
Login normally and Capture request to current API version

```http
GET /api/v2/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Attempt to access older API versions

```http
GET /api/v1/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```

or

```http
GET /api/v0/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If deprecated version responds successfully and lacks recent security controls, old API is still active
{% endstep %}

{% step %}
If older endpoint exposes additional fields or bypasses new authorization logic, improper asset management is confirmed
{% endstep %}
{% endstepper %}

***

#### Staging or Test API Exposed

{% stepper %}
{% step %}
Enumerate subdomains

```http
GET / HTTP/1.1
Host: api-staging.target.com
```

or

```http
GET / HTTP/1.1
Host: dev-api.target.com
```
{% endstep %}

{% step %}
If staging or development API responds publicly, environment isolation is missing
{% endstep %}

{% step %}
Test authentication endpoint

```http
POST /api/login HTTP/1.1
Host: api-staging.target.com
Content-Type: application/json

{"username":"test","password":"test"}
```
{% endstep %}

{% step %}
If weaker authentication or test credentials work on exposed environment, improper asset control exists
{% endstep %}

{% step %}
If non-production APIs are accessible externally, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Forgotten Internal Endpoint

{% stepper %}
{% step %}
Login as normal user and Browse JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Identify undocumented endpoint reference

```http
/api/internal/exportAllUsers
```
{% endstep %}

{% step %}
Directly access endpoint

```http
GET /api/internal/exportAllUsers HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If endpoint responds with sensitive data despite not being part of public API documentation, internal API is exposed
{% endstep %}

{% step %}
If forgotten or hidden API endpoints are accessible without restriction, improper asset management is confirmed
{% endstep %}
{% endstepper %}

***

#### Unused GraphQL Endpoint Enabled

{% stepper %}
{% step %}
Attempt access to GraphQL endpoint

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query":"{__schema{types{name}}}"}
```
{% endstep %}

{% step %}
If schema introspection is enabled and returns full API structure, hidden asset is exposed
{% endstep %}

{% step %}
Test unauthorized query

```json
{"query":"{users{id,email,password}}"}
```
{% endstep %}

{% step %}
If sensitive data fields are retrievable via undocumented GraphQL endpoint, asset governance is missing
{% endstep %}

{% step %}
If legacy or unused API services remain active and accessible, Improper Assets Management vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
