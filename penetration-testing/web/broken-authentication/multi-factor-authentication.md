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
Intercept and modify the server's response:
{% endstep %}

{% step %}
Original response:

```
{"verificationStatus":false,"mobile":9072346577,"profileId":"84673832"}
```

Change to:

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
Modify it to:

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

#### **Rate Limiting Attack on OTP Verification**

{% stepper %}
{% step %}
Navigate to the OTP verification endpoint

```
https://abc.target.com/verify/phoneno
```
{% endstep %}

{% step %}
Enter an invalid OTP (e.g., `000000`)
{% endstep %}

{% step %}
Intercept the request and send it to Intruder
{% endstep %}

{% step %}
Set the OTP field as the payload position
{% endstep %}

{% step %}
Use payload type: numbers and define a range (000000 - 999999)
{% endstep %}

{% step %}
Start the attack
{% endstep %}

{% step %}
Identify a **response length change**, which may indicate the correct OTP
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
Visit https://www.example.com/account/register/ and register a new account using attacker@example.com
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
While still in the same session, go to https://www.example.com/account/details/
{% endstep %}

{% step %}
Change the account email from attacker@example.com to victim@example.com
{% endstep %}

{% step %}
Complete any required confirmation steps for the email change (for example, entering an OTP if requested)
{% endstep %}

{% step %}
After the change, the attacker’s current trusted session is now associated with victim@example.com
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
a. Change the email back to the attacker’s email (attacker@example.com)
{% endstep %}

{% step %}
b. Re-verify the attacker email by completing the OTP and selecting “Trust this device for 1 month” again
{% endstep %}

{% step %}
c. Change the email back to victim@example.com and confirm
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
Start login with username/password so that the MFA challenge page appears (e.g., SMS or email OTP)
{% endstep %}

{% step %}
Intercept the login POST request to

POST https://auth.example.com/v3/api/login
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

Change "mode":"sms" → "mode":"email"

Change "secureLogin": true → "secureLogin": false
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

#### 2FA Bypass Via Session cloning

{% stepper %}
{% step %}
In a controlled and authorized testing environment (e.g., a test account or a program that permits testing), log into the target account and open account settings
{% endstep %}

{% step %}
Enable Two-Factor Authentication (2FA) and complete the setup (enter authenticator app code or SMS code) so that 2FA is active on the account
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Log back in using valid credentials (username/password)
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

#### Email‑based 2FA reset race condition

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

#### 2FA **race Condition** (Authentication Bypass Via a Temporary-Session-Token Race / TOCTOU)

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

#### JS File Analysis

{% stepper %}
{% step %}
Assume you are testing a web application, and you suspect that a JavaScript file may contain information about the 2FA implementation
{% endstep %}

{% step %}
Request

```http
GET /path/to/suspected-js-file.js HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Response

```http
HTTP/1.1 200 OK
Content-Type: application/javascript
```

{% hint style="info" %}
Sample JavaScript file\
This file may contain information about the 2FA implementation
{% endhint %}
{% endstep %}

{% step %}
var twoFactorEnabled = true;

var twoFactorMethod = "SMS";
{% endstep %}

{% step %}
You can then further analyze the JavaScript code to determine if there are any vulnerabilities or issues related to the 2FA implementation
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

#### CSRF On 2FA Disabling

{% stepper %}
{% step %}
Take advantage of the absence of CSRF protection to disable 2FA without the user’s knowledge
{% endstep %}

{% step %}
```http
POST /disable-2fa
Content-Type: application/json

{
"disable": true
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

#### Manipulate the OTP Parameter Values

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

#### Password Reset/Email Change Disable 2FA

{% stepper %}
{% step %}
After resetting the user’s password or changing their email, the 2FA might automatically be disabled, which could be exploited
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

### White Box

## Cheat Sheet
