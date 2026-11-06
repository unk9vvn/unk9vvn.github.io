# Multi-Factor Authentication

## Check List

## Methodology

### Black Box

#### **Manipulating OTP Verification Response**

{% stepper %}
{% step %}
Register an account with a mobile number and request an OTP
{% endstep %}

{% step %}
Enter an incorrect OTP and capture the request using Burp Suite
{% endstep %}

{% step %}
Intercept and modify the server's response
{% endstep %}

{% step %}
Original response

```
{"verificationStatus":false,"mobile":9072346577,"profileId":"84673832"}
```

Change to

```
{"verificationStatus":true,"mobile":9072346577,"profileId":"84673832"}
```
{% endstep %}

{% step %}
Forward the manipulated response
{% endstep %}

{% step %}
The system authenticates the account despite the incorrect OTP
{% endstep %}
{% endstepper %}

***

#### **Changing Error Response To Success**

{% stepper %}
{% step %}
Go to the login page and enter your phone number
{% endstep %}

{% step %}
When prompted for an OTP, enter an incorrect OTP
{% endstep %}

{% step %}
Capture the server response

```
{ "error": "Invalid OTP" }
```
{% endstep %}

{% step %}
Modify it to

```
{ "success": "true" }
```
{% endstep %}

{% step %}
Forward the response
{% endstep %}

{% step %}
If the server accepts this modification, you gain access without entering a valid OTP
{% endstep %}
{% endstepper %}

***

#### **OTP Verification Across Multiple Accounts**

{% stepper %}
{% step %}
Register two different accounts with separate phone numbers
{% endstep %}

{% step %}
Enter the correct OTP for one account and intercept the request
{% endstep %}

{% step %}
Capture the server response and note status:1 (success)
{% endstep %}

{% step %}
Now, attempt to verify the second account with an incorrect OTP
{% endstep %}

{% step %}
Intercept the server response where the status is status:0 (failure)
{% endstep %}

{% step %}
Change status:0 to status:1 and forward the response
{% endstep %}

{% step %}
If successful, you bypass OTP authentication
{% endstep %}
{% endstepper %}

***

#### **OTP Bypass Using Form Resubmission In Repeater**

{% stepper %}
{% step %}
Register an account using a **non-existent phone number**
{% endstep %}

{% step %}
Intercept the OTP request in Burp Suite
{% endstep %}

{% step %}
Send the request to Repeater and forward it
{% endstep %}

{% step %}
Modify the phone number in the request to your real number
{% endstep %}

{% step %}
If the system sends the OTP to your real number, use it to register under the fake number
{% endstep %}
{% endstepper %}

***

#### **Bypassing OTP With No Rate Limiting**

{% stepper %}
{% step %}
Create an account and request an OTP
{% endstep %}

{% step %}
Enter an incorrect OTP and capture the request in Burp Suite
{% endstep %}

{% step %}
Send the request to Burp Intruder and set a payload on the OTP field
{% endstep %}

{% step %}
Set payload type as numbers (`000000` to `999999`)
{% endstep %}

{% step %}
Start the attack
{% endstep %}

{% step %}
If no rate limit is enforced, the correct OTP will eventually match
{% endstep %}
{% endstepper %}

***

#### **Additional OTP Bypass Test Cases**

{% stepper %}
{% step %}
Default OTP Values Some applications use default OTP values such as

`111111, 123456, 000000`
{% endstep %}

{% step %}
Test common default values to check for misconfigurations OTP Leakage in Server Response Some applications leak OTPs in API responses Intercept OTP request responses and check if OTP is present&#x20;
{% endstep %}

{% step %}
Checking if Old OTP is Still Valid Some systems allow the reuse of old OTPs Test if previously used OTPs are still accepted
{% endstep %}
{% endstepper %}

***

#### OTP Bypassed By Using Luck Infused Logical Thinking <a href="#id-0112" id="id-0112"></a>

{% stepper %}
{% step %}
Register and Receive OTP Sign up on the target web app with your email and receive the 6-digit OTP
{% endstep %}

{% step %}
Intercept OTP Verification Request Use Burp Suite to capture the POST request containing the email and OTP payload
{% endstep %}

{% step %}
Test Invalid OTP Inputs Modify the payload by changing the OTP to a random value, deleting the OTP field, setting `"otp":`null, or sending an empty object
{% endstep %}

{% step %}
Send Empty OTP Payload Submit a request with the payload

`{"email": "me@example.com", "otp": ""}`
{% endstep %}

{% step %}
Verify Authentication Bypass Check if the server accepts the empty OTP and grants access to the account
{% endstep %}
{% endstepper %}

***

#### 2FA Bypass Via Parameter Tampering

{% stepper %}
{% step %}
A user would log into their Target account and enable 2FA
{% endstep %}

{% step %}
After logging out and attempting to log back in, they would be prompted for an OTP (One-Time Password)
{% endstep %}

{% step %}
Using an interception proxy like Burp Suite, the user would capture the POST request
{% endstep %}

{% step %}
Before forwarding the request, the value for the code parameter would be removed, leaving it blank
{% endstep %}

{% step %}
Upon forwarding the modified request, the server would grant access, bypassing the 2FA
{% endstep %}
{% endstepper %}

***

#### Account Takeover Via Trusted-Device Session Re-Association

{% stepper %}
{% step %}
An email address owned by the attacker (e.g. attacker@example.com)
{% endstep %}

{% step %}
A victim email address that has not registered on the site (e.g. victim@example.com)
{% endstep %}

{% step %}
Clean browser session or separate browsers for attacker and victim tests
{% endstep %}

{% step %}
Target URLs

Register: https://www.example.com/account/register/

Account details: https://www.example.com/account/details/
{% endstep %}

{% step %}
Reproduction steps (precise)
{% endstep %}

{% step %}
Create attacker account
{% endstep %}

{% step %}
Visit `https://www.example.com/account/register/` and register a new account using `attacker@example.com`
{% endstep %}

{% step %}
Complete the email OTP verification
{% endstep %}

{% step %}
During verification choose “Trust this device for 1 month” (or equivalent), creating a session that bypasses 2FA for 30 days
{% endstep %}

{% step %}
Verify you are logged in and that future logins from this device/session do not require OTP
{% endstep %}

{% step %}
Change account email to victim email
{% endstep %}

{% step %}
While still in the same session, go to `https://www.example.com/account/details/`
{% endstep %}

{% step %}
Change the account email from `attacker@example.com` to `victim@example.com`
{% endstep %}

{% step %}
Complete any required confirmation steps for the email change (for example, entering an OTP if requested)
{% endstep %}

{% step %}
After the change, the attacker’s current trusted session is now associated with `victim@example.com`
{% endstep %}

{% step %}
Confirm OTP/2FA is bypassed
{% endstep %}

{% step %}
Log out and log back in using the normal flow
{% endstep %}

{% step %}
Observe that the application does not prompt for OTP/2FA (because the session was trusted/retained)
{% endstep %}

{% step %}
This demonstrates the attacker now has an active session tied to the victim's email without the legitimate owner ever creating an account
{% endstep %}

{% step %}
Keep the bypass indefinitely
{% endstep %}

{% step %}
To persist the bypass beyond the 1-month trust window, repeat
{% endstep %}

{% step %}
a. Change the email back to the attacker’s email (`attacker@example.com`)
{% endstep %}

{% step %}
b. Re-verify the attacker email by completing the OTP and selecting “Trust this device for 1 month” again
{% endstep %}

{% step %}
c. Change the email back to `victim@example.com` and confirm
{% endstep %}

{% step %}
Each cycle re-establishes a new trusted session which the attacker then re-associates with the victim email
{% endstep %}
{% endstepper %}

***

#### 2FA Bypass Via Parameter Tampering

{% stepper %}
{% step %}
Enable MFA for the account (if not already)
{% endstep %}

{% step %}
Start login with username/password so that the MFA challenge page appears (SMS or email OTP)
{% endstep %}

{% step %}
Intercept the login `POST` request to

`POST https://auth.example.com/v3/api/login`
{% endstep %}

{% step %}
Inspect the JSON body and locate fields similar to

```json
{
  "username":"you@example.com",
  "password":"YourPassword",
  "mode":"sms",
  "secureLogin": true,
  ...
}
```
{% endstep %}

{% step %}
Modify the request body before forwarding

Change `"mode":"sms"` → `"mode":"email"`

Change `"secureLogin": true` → `"secureLogin": false`
{% endstep %}

{% step %}
(In some implementations the exact words/values ​​may be different; change the logically equivalent fields)
{% endstep %}

{% step %}
Forward/send the modified request
{% endstep %}

{% step %}
The client will be logged into the account without providing the MFA code
{% endstep %}
{% endstepper %}

***

#### 2FA Bypass Via Session Coning

{% stepper %}
{% step %}
In a controlled and authorized testing environment (a test account or a program that permits testing), log into the target account and open account settings
{% endstep %}

{% step %}
Enable Two-Factor Authentication (2FA) and complete the setup (enter authenticator app code or SMS code) so that 2FA is active on the account
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Log back in using valid credentials `(username`/`password`)
{% endstep %}

{% step %}
When prompted, enter the valid 2FA code and complete the login so a new session is established
{% endstep %}

{% step %}
Using a cookie management/export tool (for example a Cookie Editor extension, the browser devtools, or a proxy tool that exposes cookies), export the session cookies for that logged-in session and copy the full cookie values
{% endstep %}

{% step %}
Open a different browser or a separate browser profile that is not currently logged into the account (or use a separate device/environment)
{% endstep %}

{% step %}
Import/paste the copied cookies into that other browser/profile using the same cookie names and values you extracted in step 6 (or overwrite the existing cookies via devtools)
{% endstep %}

{% step %}
Refresh the site or navigate to the account dashboard in the second browser
{% endstep %}

{% step %}
Observe that you can access the account content without being prompted for the 2FA code — the session cookies allowed access and 2FA was bypassed
{% endstep %}

{% step %}
(Optional) For verification, invalidate or log out the original session in the first browser and check whether the cookie-based session in the second browser still grants access
{% endstep %}
{% endstepper %}

***

#### Email‑Based 2FA Reset Race Condition

{% stepper %}
{% step %}
Log into your account and enable Two-Factor Authentication (2FA)
{% endstep %}

{% step %}
Log out of your account
{% endstep %}

{% step %}
Log back in, enter your username and password, but do not enter your TOTP code
{% endstep %}

{% step %}
Click on “Reset two-factor authentication” and confirm the action by pressing OK
{% endstep %}

{% step %}
You will receive an email from the platform that contains an option to cancel the 2FA reset request
{% endstep %}

{% step %}
Do not interact with the email — do not open it or click any links
{% endstep %}

{% step %}
Wait for one full day (24 hours) without taking any action
{% endstep %}

{% step %}
After a day, return to the site and log in again
{% endstep %}

{% step %}
You will notice that 2FA has been automatically disabled, allowing you to log in successfully without providing a 2FA code — meaning an attacker could fully take over the victim’s account if the victim doesn’t cancel the request in time
{% endstep %}
{% endstepper %}

***

#### 2FA R**ace Condition** (Authentication Bypass Via a Temporary-Session-Token Race / TOCTOU)

{% stepper %}
{% step %}
Target an application that uses a GraphQL API with Two-Factor Authentication (2FA) enabled
{% endstep %}

{% step %}
Analyze the login flow and confirm it has two steps
{% endstep %}

{% step %}
Step 1 Send username and password → the server responds with “2FA required” and issues a temporary session token
{% endstep %}

{% step %}
Step 2 Send the 2FA code along with that token for verification
{% endstep %}

{% step %}
Identify the race window between Step 1 and Step 2 — the temporary token becomes active before the 2FA verification is completed
{% endstep %}

{% step %}
Exploit this timing issue by sending two nearly simultaneous requests
{% endstep %}

{% step %}
Request A: The valid 2FA code submission (legitimate step)
{% endstep %}

{% step %}
Request B: An authenticated GraphQL query such as

```graphql
{ me { email } }
```
{% endstep %}

{% step %}
using the same temporary session token from Step 1
{% endstep %}

{% step %}
Use a tool like curl or a Python script (with threading or asynchronous requests) to fire both requests at the same time, ensuring that Request B reaches the server before Request A completes
{% endstep %}

{% step %}
If the race condition succeeds, the server will return sensitive user data (e.g., email) from Request B, even though 2FA verification is not finished
{% endstep %}

{% step %}
This demonstrates a 2FA Authentication Bypass caused by improper state management during the authentication flow
{% endstep %}

{% step %}
Repeat multiple times to confirm timing consistency and determine the reliability of the race condition
{% endstep %}
{% endstepper %}

***

#### Response Manipulation

{% stepper %}
{% step %}
Log into the test account, enable Two-Factor Authentication (2FA) in account settings, then log out
{% endstep %}

{% step %}
Now enable your proxy and turn on interception. In the 2FA entry form enter a random/invalid code and submit the request
{% endstep %}

{% step %}
In the proxy locate the 2FA verification request/response. The server response typically contains JSON or a flag such as `{ "ready": false }` indicating 2FA is not yet confirmed
{% endstep %}

{% step %}
Edit the response body: change the relevant field from false to true — e.g. modify `{ "ready": false } to { "ready": true }` (or the equivalent boolean field present in the real API response)
{% endstep %}

{% step %}
Forward the modified response back to the client
{% endstep %}

{% step %}
Refresh/wait for redirect — you should be taken to the dashboard and gain account access without providing a valid 2FA code, demonstrating a 2FA bypass
{% endstep %}

{% step %}
Repeat multiple times to confirm reproducibility and success rate. Clean up the test account or disable 2FA afterwards
{% endstep %}
{% endstepper %}

***

#### Status Code Manipulation

{% stepper %}
{% step %}
Change the HTTP status code from a 4xx (indicating authentication failure) to a 200 OK status code to see if it allows access. This can trick the system into thinking the authentication was successful
{% endstep %}

{% step %}
Original Response

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json 

{ 
"error": "Invalid credentials" 
}// Some code
```
{% endstep %}

{% step %}
Edited Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
"error": "Invalid credentials"
}
```
{% endstep %}
{% endstepper %}

***

#### 2FA Code Leakage In Response

{% stepper %}
{% step %}
Check the response of the 2FA Code Triggering Request to see if the 2FA code is leaked in the response body. If it is, it could be used to authenticate without going through the proper 2FA process
{% endstep %}

{% step %}
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
"message": "Authentication successful",
"2fa_code": "123456"
}
```
{% endstep %}
{% endstepper %}

***

#### 2FA Code Reusability

{% stepper %}
{% step %}
Generate a 2FA code and use it for authentication. Attempt to reuse the same 2FA code in a different session. Successful reuse may indicate a security vulnerability
{% endstep %}

{% step %}
```http
POST /authenticate
Content-Type: application/json

{
"username": "user123",
"2fa_code": "123456"
}
```
{% endstep %}
{% endstepper %}

***

#### Lack of Brute-Force Protection

{% stepper %}
{% step %}
Exploit the absence of rate limiting on the 2FA API to brute-force the 2FA code. Try various codes until you find the correct one. You can use Burps Suite’s Intruder tool for the same
{% endstep %}

{% step %}
```http
POST /2fa
Content-Type: application/json

{
"username": "user123",
"2fa_code": "123456"
}
```
{% endstep %}
{% endstepper %}

***

#### Missing 2FA Code Integrity Validation

{% stepper %}
{% step %}
Exploit the absence of code integrity validation to check if you can use the same 2FA code for another user’s 2FA validation
{% endstep %}

{% step %}
```http
POST /authenticate
Content-Type: application/json

{
"username": "user123",
"2fa_code": "123456"
}
```
{% endstep %}
{% endstepper %}

***

#### Bypass 2FA Using The “Remember Me” Functionality

{% stepper %}
{% step %}
Attempt to bypass 2FA by using the “remember me” functionality, which may store 2FA information in a cookie, session, local storage, or IP address
{% endstep %}

{% step %}
```http
POST /authenticate
Content-Type: application/json

{
"username": "user123",
"remember_me": true
}
```
{% endstep %}

{% step %}
If you select this option and log in with the correct 2FA code for the first time, the system will create a long-term token or cookie; from then on, you can log in directly without the need for a 2FA code, even with a new device or browser
{% endstep %}
{% endstepper %}

***

#### 2FA Refer Check Bypass

{% stepper %}
{% step %}
Navigate to an authenticated page and, if unsuccessful, change the Referer header to the 2FA page URL to trick the application into thinking the request came after satisfying 2FA
{% endstep %}

{% step %}
```http
GET /authenticated-page
Referer: https://example.com/2fa
```
{% endstep %}

{% step %}
If the application only checks whether the user has passed 2FA based on the Referer header, this change will take you directly to the protected page and bypass 2FA
{% endstep %}
{% endstepper %}

***

#### Sequential OTP Number

{% stepper %}
{% step %}
Check if the OTPs generated are sequential, allowing you to predict the next OTP. This can be exploited if the system generates predictable OTPs
{% endstep %}

{% step %}
Valid OTP Request 1

```http
POST /request-otp
Content-Type: application/json

{
"2fa": "500060"
}
```
{% endstep %}

{% step %}
Valid OTP Request 2

```http
POST /request-otp
Content-Type: application/json

{
"2fa": "500061"
}
```
{% endstep %}
{% endstepper %}

***

#### Remove The OTP Parameter

{% stepper %}
{% step %}
Attempt to bypass 2FA by removing the OTP parameter from the request
{% endstep %}

{% step %}
Original Request

```http
POST /validate-otp 
Content-Type: application/json 

{ 
"email": "user@email.com",
"2fa": "500061" 
}
```
{% endstep %}

{% step %}
Modified Request

```http
POST /validate-otp 
Content-Type: application/json 

{ 
"email": "user@email.com"
}
```
{% endstep %}
{% endstepper %}

***

#### Manipulate The OTP Parameter Values

{% stepper %}
{% step %}
Try various manipulations of the OTP parameter to see if you can bypass 2FA
{% endstep %}

{% step %}
```http
POST /validate-otp 
Content-Type: application/json 
{
    "2fa": "123456", // make it "2fa": ""
    "2fa": "123456", // make it "2fa": "null"
    "2fa": "123456", // make it "2fa": "true"
    "2fa": "123456", // make it "2fa": null
    "2fa": "123456", // make it "2fa": "00000"
}
```
{% endstep %}
{% endstepper %}

***

#### 2FA Code Validity

{% stepper %}
{% step %}
Request multiple 2FA codes, and check if previously requested 2FA codes can be used to authenticate
{% endstep %}

{% step %}
Request for MFA Code, wait for a longer time, and try using the same code; successful use may indicate a security vulnerability
{% endstep %}
{% endstepper %}

***

#### 2FA Bypass Via Race Condition

{% stepper %}
{% step %}
Begin the login flow for the test account: submit username/password and reach the step where the service indicates “2FA required.” The server should issue a temporary session token/JWT and present the OTP entry page
{% endstep %}

{% step %}
Using your proxy, intercept the OTP verification request to the server. Instead of forwarding it normally, drop the request or cut the connection just before the verification response is received—simulating a network failure or the user closing the tab at the moment of verification
{% endstep %}

{% step %}
Without completing the OTP round-trip, manually navigate back to the site (e.g., homepage or dashboard) in the browser and check whether the session appears authenticated. If you are logged in, the token/session was activated too early and 2FA has been bypassed
{% endstep %}

{% step %}
If successful, inspect proxy logs/history to confirm whether an Authorization header (e.g., a Bearer token) was present/activated before OTP verification completed. (Do this only in a test environment and do not publish real token values)
{% endstep %}

{% step %}
To demonstrate impact, use the current token/session to call authenticated API endpoints and perform high-impact actions (view email, change settings, invoke sensitive endpoints) to show full account access is possible without 2FA
{% endstep %}

{% step %}
After the vendor patches the main UI flow, re-test by attempting the same bypass and also by calling backend API endpoints (e.g., direct /api/v2/\* endpoints) to see if any endpoints were missed by the patch—testing for incomplete fixes
{% endstep %}

{% step %}
Repeat the sequence multiple times with varied timing to map the race window and determine reliability
{% endstep %}

{% step %}
Collect non-sensitive evidence (sanitized logs, video of the flow without revealing real tokens/OTPs) and submit a responsible disclosure report. Clean up afterwards by invalidating sessions or removing the test account
{% endstep %}
{% endstepper %}

***

#### OTP Bypass Via Internal Paths

{% stepper %}
{% step %}
Log in to the target site then complete the authentication process with Account A
{% endstep %}

{% step %}
After authentication, note down the internal paths like

```http
/dashboard
/settings
/profile/edit
```
{% endstep %}

{% step %}
Then log out and complete the authentication process with account B until you reach the OTP verification stage
{% endstep %}

{% step %}
Do not complete the OTP. On the same OTP verification page, enter one of the internal paths you noted, such as `/profile/edit`. If you enter, the vulnerability will be confirmed
{% endstep %}
{% endstepper %}

***

#### Login Bypassed & MFA Using a Race Condition + JWT Leak

{% stepper %}
{% step %}
Navigate to the target application's login page
{% endstep %}

{% step %}
Have or create a valid user account with MFA enabled
{% endstep %}

{% step %}
Prepare a list of password attempts that includes the correct password
{% endstep %}

{% step %}
Using Burp Suite (Repeater or Intruder in parallel mode)

* Send **50+ login requests simultaneously**
* All requests must use the same email with different passwords
{% endstep %}

{% step %}
Launch all requests at the same time to trigger a race condition
{% endstep %}

{% step %}
Observe that despite exceeding the failed login threshold:

* The account is not locked
* The server returns a **valid JWT** in one of the responses
{% endstep %}

{% step %}
Decode the returned JWT
{% endstep %}

{% step %}
Verify that the JWT contains an `authCode` or OTP-related value
{% endstep %}

{% step %}
Proceed to the OTP verification step
{% endstep %}

{% step %}
Using the valid JWT:

* Submit any random or incorrect OTP
{% endstep %}

{% step %}
Observe that authentication succeeds and

* Login completes without a valid OTP
* Access to the user account is granted
{% endstep %}
{% endstepper %}

***

#### s

{% stepper %}
{% step %}
Visit the target platform’s login or signup page as an unauthenticated user
{% endstep %}

{% step %}
Enter any arbitrary or fake email address to trigger the platform’s telemetry or tracking endpoint
{% endstep %}

{% step %}
Capture the issued **guest JWT token** from browser storage, response headers, or API responses
{% endstep %}

{% step %}
Capture the issued **guest JWT token** from browser storage, response headers, or API responses
{% endstep %}

{% step %}
Store all collected JWT tokens in a file (`jwt.json`)
{% endstep %}

{% step %}
Register a new account using the **victim’s real email address** (`victim@victim.com`) to trigger the OTP email delivery
{% endstep %}

{% step %}
Intercept or craft requests to the OTP validation endpoint like

```http
POST /ups/api/activation/validate
```
{% endstep %}

{% step %}
Send OTP validation requests using one JWT token for up to **10 incorrect OTP attempts**
{% endstep %}

{% step %}
Upon receiving an HTTP 429 Too Many Requests response, switch the `Authorization` header to a new JWT token
{% endstep %}

{% step %}
Continue sending OTP validation requests while rotating JWT tokens every 10 attempts
{% endstep %}

{% step %}
Repeat the process until the correct 6-digit OTP is guessed
{% endstep %}

{% step %}
Observe a 200 OK response indicating successful email verification
{% endstep %}

{% step %}
Confirm that the victim’s email address is now verified and the account is activated without the attacker ever accessing the victim’s inbox
{% endstep %}
{% endstepper %}

***

### White Box

#### MFA Enforcement Bypass via Missing Server-Side State Check (Forced Browsing Past the Second Factor

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Trigger a full login on an account that has MFA enabled while proxying through Burp, and record every request in the flow: the first-factor endpoint (username/password), the second-factor endpoint (`OTP/push/U2F` verification), and the first protected endpoint hit right after a successful login
{% endstep %}

{% step %}
In the decompiled code, locate the handler for the first-factor endpoint and identify exactly what session, token, or cookie state it sets on success — pay attention to whether it immediately marks the session as fully authenticated or only as "pending second factor"
{% endstep %}

{% step %}
Locate the handler for a protected resource that should only be reachable after MFA, and identify exactly which attribute it checks to authorize the request
{% endstep %}

{% step %}
Compare the attribute written in step 5 with the attribute read in step 6 — if the protected handler checks a coarse flag (e.g. `authenticated`/`loggedIn`) instead of a dedicated factor-completion flag (e.g. `mfaVerified`), the second factor is enforced only by the client-side redirect, not by the server

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(Session\.SetString\(\s*"Authenticated")|(Session\.SetString\(\s*"LoggedIn")|(GetString\(\s*"Authenticated"\)\s*!=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(session\.setAttribute\(\s*"authenticated")|(session\.setAttribute\(\s*"loggedIn")|(session\.getAttribute\(\s*"authenticated"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$_SESSION\[\s*['"]authenticated['"]\s*\]\s*=)|(\$_SESSION\[\s*['"]logged_in['"]\s*\]\s*=)|(empty\(\$_SESSION\[\s*['"]authenticated['"]\s*\]\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(req\.session\.authenticated\s*=)|(req\.session\.isAuthenticated\s*=)|(req\.session\.loggedIn\s*=)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
Session\.SetString\(\s*"Authenticated"|Session\.SetString\(\s*"LoggedIn"|GetString\(\s*"Authenticated"\)\s*!=
```
{% endtab %}

{% tab title="Java" %}
```regexp
session\.setAttribute\(\s*"authenticated"|session\.setAttribute\(\s*"loggedIn"|session\.getAttribute\(\s*"authenticated"\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_SESSION\[\s*['"]authenticated['"]\s*\]\s*=|\$_SESSION\[\s*['"]logged_in['"]\s*\]\s*=|empty\(\$_SESSION\[\s*['"]authenticated['"]\s*\]\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.session\.authenticated\s*=|req\.session\.isAuthenticated\s*=|req\.session\.loggedIn\s*=
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost("login")]
public IActionResult Login([FromBody] LoginRequest req)
{
    var user = _authService.ValidateCredentials(req.Username, req.Password);
    if (user == null)
        return Unauthorized();
 
    HttpContext.Session.SetString("Authenticated", "true"); // [1]
    HttpContext.Session.SetString("UserId", user.Id.ToString());
 
    if (user.MfaEnabled)
    {
        HttpContext.Session.SetString("MfaVerified", "false"); // [2]
        return Ok(new { mfaRequired = true });
    }
 
    return Ok(new { mfaRequired = false });
}
 
[HttpGet("account/invoices")]
public IActionResult GetInvoices()
{
    if (HttpContext.Session.GetString("Authenticated") != "true") // [3]
        return Unauthorized();
 
    var userId = HttpContext.Session.GetString("UserId");
    return Ok(_invoiceService.GetForUser(userId));
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpSession session) {
    User user = authService.validateCredentials(req.getUsername(), req.getPassword());
    if (user == null) {
        return ResponseEntity.status(401).build();
    }
 
    session.setAttribute("authenticated", true); // [1]
    session.setAttribute("userId", user.getId());
 
    if (user.isMfaEnabled()) {
        session.setAttribute("mfaVerified", false); // [2]
        return ResponseEntity.ok(Map.of("mfaRequired", true));
    }
 
    return ResponseEntity.ok(Map.of("mfaRequired", false));
}
 
@GetMapping("/account/invoices")
public ResponseEntity<?> getInvoices(HttpSession session) {
    Boolean authenticated = (Boolean) session.getAttribute("authenticated"); // [3]
    if (authenticated == null || !authenticated) {
        return ResponseEntity.status(401).build();
    }
 
    Long userId = (Long) session.getAttribute("userId");
    return ResponseEntity.ok(invoiceService.getForUser(userId));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function login($username, $password) {
    $user = AuthService::validateCredentials($username, $password);
    if ($user === null) {
        http_response_code(401);
        return;
    }
 
    $_SESSION['authenticated'] = true; // [1]
    $_SESSION['user_id'] = $user->id;
 
    if ($user->mfa_enabled) {
        $_SESSION['mfa_verified'] = false; // [2]
        echo json_encode(['mfaRequired' => true]);
        return;
    }
 
    echo json_encode(['mfaRequired' => false]);
}
 
function getInvoices() {
    if (empty($_SESSION['authenticated'])) { // [3]
        http_response_code(401);
        return;
    }
 
    echo json_encode(InvoiceService::getForUser($_SESSION['user_id']));
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post('/login', async (req, res) => {
  const user = await authService.validateCredentials(req.body.username, req.body.password);
  if (!user) return res.status(401).end();
 
  req.session.authenticated = true; // [1]
  req.session.userId = user.id;
 
  if (user.mfaEnabled) {
    req.session.mfaVerified = false; // [2]
    return res.json({ mfaRequired: true });
  }
 
  return res.json({ mfaRequired: false });
});
 
app.get('/account/invoices', (req, res) => {
  if (!req.session.authenticated) { // [3]
    return res.status(401).end();
  }
 
  res.json(invoiceService.getForUser(req.session.userId));
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers in the code above: `[1]` the coarse session flag is set immediately after the first factor succeeds, before any OTP has been submitted. `[2]` a dedicated factor-completion flag does exist in the data model. `[3]` the protected resource never reads it — it only checks the coarse flag from `[1]`, so the flag from `[2]` is effectively dead code from an authorization standpoint
{% endstep %}

{% step %}
Confirm the bypass by sending only the first-factor request, capturing the resulting session cookie/token, and replaying it directly against the protected endpoint without ever calling the OTP-verification endpoint

```http
POST /login HTTP/1.1
Host: target.tld
Content-Type: application/json
Content-Length: 51
 
{"username":"alice","password":"Sup3rSecret!"}
```

```
HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOi...; HttpOnly
Content-Type: application/json
 
{"mfaRequired":true}
```
{% endstep %}

{% step %}
Replay the session cookie against the protected resource without ever solving the OTP step

```http
GET /account/invoices HTTP/1.1
Host: target.tld
Cookie: session=eyJhbGciOi...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
 
[{"id":1,"amount":"1200.00"},{"id":2,"amount":"640.00"}]
```

If real account data is returned instead of a redirect to the OTP page or a 401, the second factor is confirmed to be a client-side-only control
{% endstep %}
{% endstepper %}

***

#### MFA Bypass via Client-Controlled Verification Result (Forging the Second-Factor Outcome

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Trigger a full successful MFA login while proxying through Burp, paying special attention to multi-step flows where a "verify-otp" call returns a short-lived ticket/token and a separate "finalize" or "exchange" call turns that ticket into a fully authenticated session
{% endstep %}

{% step %}
In the decompiled code, locate the handler for the finalize/exchange endpoint and identify exactly which fields it trusts directly from the request body versus which fields it independently re-validates against server-side state (database row, cache entry, signed ticket)
{% endstep %}

{% step %}
Check whether the finalize handler accepts a boolean or string field describing the OTP outcome itself (e.g. `otpVerified`, `mfaStatus`, `factorResult`) instead of deriving that outcome from a previously issued, server-signed ticket ID
{% endstep %}

{% step %}
If such a field exists and is not cryptographically bound to a prior server-side verification step, the second factor can be forged entirely on the client

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.OtpVerified\b)|(\.MfaVerified\b)|(\.FactorVerified\b)|(\.TwoFactorVerified\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(isOtpVerified\s*\()|(isMfaVerified\s*\()|(getOtpStatus\s*\()|(getFactorResult\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\[\s*['"]otpVerified['"]\s*\])|(\[\s*['"]otp_verified['"]\s*\])|(\[\s*['"]mfaVerified['"]\s*\])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(req\.body\.otpVerified)|(req\.body\.mfaVerified)|(req\.body\.otpStatus)|(req\.body\.factorResult)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
\.OtpVerified\b|\.MfaVerified\b|\.FactorVerified\b|\.TwoFactorVerified\b
```
{% endtab %}

{% tab title="Java" %}
```regexp
isOtpVerified\s*\(|isMfaVerified\s*\(|getOtpStatus\s*\(|getFactorResult\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\[\s*['"]otpVerified['"]\s*\]|\[\s*['"]otp_verified['"]\s*\]|\[\s*['"]mfaVerified['"]\s*\]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.body\.otpVerified|req\.body\.mfaVerified|req\.body\.otpStatus|req\.body\.factorResult
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public class FinalizeMfaRequest
{
    public string Username { get; set; }
    public bool OtpVerified { get; set; } // [1]
}
 
[HttpPost("mfa/finalize")]
public IActionResult FinalizeMfa([FromBody] FinalizeMfaRequest req)
{
    if (req.OtpVerified) // [2]
    {
        var user = _userRepository.GetByUsername(req.Username);
        var token = _tokenService.IssueSessionToken(user); // [3]
        return Ok(new { token });
    }
 
    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class FinalizeMfaRequest {
    private String username;
    private boolean otpVerified; // [1]
 
    public String getUsername() { return username; }
    public boolean isOtpVerified() { return otpVerified; }
}
 
@PostMapping("/mfa/finalize")
public ResponseEntity<?> finalizeMfa(@RequestBody FinalizeMfaRequest req) {
    if (req.isOtpVerified()) { // [2]
        User user = userRepository.getByUsername(req.getUsername());
        String token = tokenService.issueSessionToken(user); // [3]
        return ResponseEntity.ok(Map.of("token", token));
    }
 
    return ResponseEntity.status(401).build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function finalizeMfa($request) {
    // [1] the verification outcome travels inside the client request body
    if (!empty($request['otpVerified']) && $request['otpVerified'] === true) { // [2]
        $user = UserRepository::getByUsername($request['username']);
        $token = TokenService::issueSessionToken($user); // [3]
        echo json_encode(['token' => $token]);
        return;
    }
 
    http_response_code(401);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post('/mfa/finalize', async (req, res) => {
  // [1] the verification outcome travels inside the client request body
  if (req.body.otpVerified === true) { // [2]
    const user = await userRepository.getByUsername(req.body.username);
    const token = tokenService.issueSessionToken(user); // [3]
    return res.json({ token });
  }
 
  return res.status(401).end();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the OTP outcome is a plain field on the client-supplied DTO rather than something derived server-side, `[2]` the handler branches purely on that client-controlled value, `[3]` a fully privileged session token is minted with no reference back to a real OTP-verify call, so the value can simply be forged
{% endstep %}

{% step %}
Build a request to the finalize endpoint that supplies only the first-factor identity plus the forged outcome field, without ever calling the real verify-otp endpoint, and send it directly

```http
POST /mfa/finalize HTTP/1.1
Host: target.tld
Content-Type: application/json
Content-Length: 41
 
{"username":"alice","otpVerified":true}
```

```
HTTP/1.1 200 OK
Content-Type: application/json
 
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```
{% endstep %}

{% step %}
If a valid, fully authenticated token is returned, the second factor has been bypassed entirely client-side
{% endstep %}
{% endstepper %}

***

#### MFA Bypass via Missing Rate Limiting / Attempt Counter on OTP Verification (Brute-Forceable Second Factor)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Trigger the OTP-verification endpoint with an intentionally wrong code several times in a row and observe whether the response, status code, latency, or account state changes after repeated failures
{% endstep %}

{% step %}
In the decompiled code, locate the handler for the OTP-verify endpoint and trace exactly how the submitted code is compared against the expected value — check whether the comparison happens directly, with no attempt counter or lockout flag read or written beforehand
{% endstep %}

{% step %}
Check whether a failed-attempt counter exists at all in the data/session model and, if it exists, whether it is actually enforced (request rejected once a threshold is reached) or only incremented for logging purposes with no enforcement
{% endstep %}

{% step %}
Check whether the OTP itself is short and long-lived enough to brute-force within its validity window (a `6-digit` numeric code valid for several minutes, with no per-IP or per-account throttling)
{% endstep %}

{% step %}
Check whether the comparison logic accepts any additional fixed value left over from testing/debugging in addition to the real code

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(==\s*expectedCode)|(==\s*"000000")|(==\s*"123456")
```
{% endtab %}

{% tab title="Java" %}
```regexp
(\.equals\(\s*expectedCode\))|(\.equals\(\s*"000000"\))|(\.equals\(\s*"123456"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(==\s*\$expectedCode)|(==\s*['"]000000['"])|(==\s*['"]123456['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(===\s*expectedCode)|(===\s*['"]000000['"])|(===\s*['"]123456['"])
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
==\s*expectedCode|==\s*"000000"|==\s*"123456"
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.equals\(\s*expectedCode\)|\.equals\(\s*"000000"\)|\.equals\(\s*"123456"\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
==\s*\$expectedCode|==\s*['"]000000['"]|==\s*['"]123456['"]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
===\s*expectedCode|===\s*['"]000000['"]|===\s*['"]123456['"]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost("mfa/verify")]
public IActionResult VerifyOtp([FromBody] VerifyOtpRequest req)
{
    var pendingUserId = HttpContext.Session.GetString("PendingUserId");
    var expectedCode = _otpStore.GetCode(pendingUserId); // [1]
 
    if (req.Code == expectedCode || req.Code == "000000") // [2]
    {
        HttpContext.Session.SetString("Authenticated", "true");
        return Ok();
    }
 
    return Unauthorized(); // [3]
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/mfa/verify")
public ResponseEntity<?> verifyOtp(@RequestBody VerifyOtpRequest req, HttpSession session) {
    String pendingUserId = (String) session.getAttribute("pendingUserId");
    String expectedCode = otpStore.getCode(pendingUserId); // [1]
 
    if (req.getCode().equals(expectedCode) || req.getCode().equals("000000")) { // [2]
        session.setAttribute("authenticated", true);
        return ResponseEntity.ok().build();
    }
 
    return ResponseEntity.status(401).build(); // [3]
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function verifyOtp($request) {
    $pendingUserId = $_SESSION['pending_user_id'];
    $expectedCode = OtpStore::getCode($pendingUserId); // [1]
 
    if ($request['code'] == $expectedCode || $request['code'] == '000000') { // [2]
        $_SESSION['authenticated'] = true;
        http_response_code(200);
        return;
    }
 
    http_response_code(401); // [3]
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post('/mfa/verify', (req, res) => {
  const pendingUserId = req.session.pendingUserId;
  const expectedCode = otpStore.getCode(pendingUserId); // [1]
 
  if (req.body.code === expectedCode || req.body.code === '000000') { // [2]
    req.session.authenticated = true;
    return res.status(200).end();
  }
 
  return res.status(401).end(); // [3]
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` no attempt counter is read or incremented before the comparison runs, `[2]` a leftover debug bypass value (`000000`) is accepted alongside the real code, `[3]` a failed attempt simply returns 401 with no delay, lockout, or counter increment, so the endpoint can be hit at full request speed
{% endstep %}

{% step %}
First test the leftover debug value directly against a captured pending session

```http
POST /mfa/verify HTTP/1.1
Host: target.tld
Content-Type: application/json
Cookie: session=eyJhbGciOi...
Content-Length: 17
 
{"code":"000000"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
 
{"authenticated":true}
```
{% endstep %}

{% step %}
If the debug code does not work, use Burp Intruder against the same pending session cookie to cycle through the full numeric keyspace (`000000`–`999999`) of the OTP and observe whether any request is throttled, delayed, or triggers a lockout
{% endstep %}

{% step %}
If the account never locks, throttles, or otherwise reacts after dozens or hundreds of failed attempts, the second factor is brute-forceable within its validity window, confirming the vulnerability\\
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
