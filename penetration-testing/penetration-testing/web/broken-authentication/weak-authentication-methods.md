# Weak Authentication Methods

## Check List

## Methodology

### Black Box

#### Authentication Weakness

{% stepper %}
{% step %}
Create an account or change the password to evaluate the password policy
{% endstep %}

{% step %}
Test simple passwords (only numbers, only letters, short passwords, common ones like 123456) and check whether they are accepted
{% endstep %}

{% step %}
Identify the minimum and maximum password length by testing very short and very long passwords
{% endstep %}

{% step %}
Try using the username or personal information inside the password and observe the result.
{% endstep %}

{% step %}
Change the password multiple times and attempt to reuse a previous password
{% endstep %}

{% step %}
Perform multiple failed login attempts and check whether account lockout or rate limiting is enforced
{% endstep %}

{% step %}
If alternative factors such as PIN or security questions exist, test whether they are guessable or vulnerable to brute force
{% endstep %}

{% step %}
Finally, determine whether weaknesses exist in password complexity, password reuse protection, or brute-force protection
{% endstep %}
{% endstepper %}

***

### White Box

#### Weak Authentication Mechanism (Hardcoded Credentials)

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all authentication entry points
{% endstep %}

{% step %}
In the source code, review related services, and look for weak authentication implementations such as Basic Auth, No Auth, or simple tokens

{% tabs %}
{% tab title="C#" %}
```csharp
public IActionResult Login(string username, string password)
{
    if (username == "admin" && password == "123456")
    {
        return Ok("Login Success");
    }

    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
public Object Login(String username, String password)
{
    if (username.equals("admin") && password.equals("123456"))
    {
        return Ok("Login Success");
    }

    return Unauthorized();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function Login($username, $password)
{
    if ($username == "admin" && $password == "123456")
    {
        return Ok("Login Success");
    }

    return Unauthorized();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function Login(username, password)
{
    if (username == "admin" && password == "123456")
    {
        return Ok("Login Success");
    }

    return Unauthorized();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then inspect the Authentication Controller or Service and determine whether validation is based only on simple string comparison or insecure conditions

{% tabs %}
{% tab title="C#" %}
```csharp
public bool Authenticate(string token)
{
    return token == "static-token-123";
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean authenticate(String token)
{
    return token.equals("static-token-123");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function Authenticate($token)
{
    return $token == "static-token-123";
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function authenticate(token)
{
    return token == "static-token-123";
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether weak algorithms are used for token generation or validation, such as fixed GUIDs, unsigned JWTs, or predictable hashes

{% tabs %}
{% tab title="C#" %}
```csharp
var token = "user-" + username + "-token";
return token;
```
{% endtab %}

{% tab title="Java" %}
```java
String token = "user-" + username + "-token";
return token;
```
{% endtab %}

{% tab title="PHP" %}
```php
$token = "user-" . $username . "-token";
return $token;
```
{% endtab %}

{% tab title="Node.js" %}
```js
const token = "user-" + username + "-token";
return token;
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review password policy logic and determine whether minimum length, complexity, expiration, or history rules are enforced

{% tabs %}
{% tab title="C#" %}
```csharp
if (password.Length < 4)
{
    return BadRequest("Weak password");
}
```
{% endtab %}

{% tab title="Java" %}
```java
if (password.length() < 4)
{
    return BadRequest("Weak password");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if (strlen($password) < 4)
{
    return BadRequest("Weak password");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
if (password.length < 4)
{
    return BadRequest("Weak password");
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In MFA and OTP implementations, determine whether one-time codes are predictable, static, or without expiration

{% tabs %}
{% tab title="C#" %}
```csharp
public string GenerateOtp()
{
    return "123456";
}
```
{% endtab %}

{% tab title="Java" %}
```java
public String generateOtp()
{
    return "123456";
}
```
{% endtab %}

{% tab title="PHP" %}
```php

public function GenerateOtp()
{
    return "123456";
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function generateOtp()
{
    return "123456";
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the authentication flow, determine whether alternative mechanisms such as Password Reset, Magic Link, or API Login exist without proper security controls

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("reset-password")]
public IActionResult Reset(string email)
{
    return Ok("Reset Link: " + "http://example.com/reset?token=static");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("reset-password")
public Object reset(String email)
{
    return Ok("Reset Link: " + "http://example.com/reset?token=static");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpGet("reset-password")]
public function Reset($email)
{
    return Ok("Reset Link: " . "http://example.com/reset?token=static");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.get("/reset-password", (req, res) => {
    return Ok("Reset Link: " + "http://example.com/reset?token=static");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify endpoints that are accessible without authentication but still expose sensitive data or valid tokens

{% tabs %}
{% tab title="C#" %}
```csharp
[AllowAnonymous]
[HttpGet("api/user-info")]
public IActionResult GetUser()
{
    return Ok(_userService.GetAllUsers());
}
```
{% endtab %}

{% tab title="Java" %}
```java
@AllowAnonymous
@GetMapping("api/user-info")
public Object getUser()
{
    return Ok(_userService.getAllUsers());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[AllowAnonymous]
#[HttpGet("api/user-info")]
public function GetUser()
{
    return Ok($this->_userService->GetAllUsers());
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.get("/api/user-info", (req, res) => {
    return Ok(_userService.getAllUsers());
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Finally, test all authentication paths using weak credentials, predictable tokens, static OTPs, or unauthenticated endpoints, and determine whether unauthorized access to accounts or APIs is possible
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
