# Race Conditions

## Check List

## Cheat Sheet

## Methodology&#x20;

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition)

#### Race Condition / Concurrency Testing

{% stepper %}
{% step %}
Create a free account on target
{% endstep %}

{% step %}
Navigate to the section offering “Claim Free \<resource>” or “Purchase \<item>”
{% endstep %}

{% step %}
Trigger the action and observe the redirect or request to

`https:///api//start?item=<resource_name>`<br>
{% endstep %}

{% step %}
Capture the final transaction request

```http
POST /api/v1/<api-endpoint>
```
{% endstep %}

{% step %}
Duplicate this request 5–15 times
{% endstep %}

{% step %}
Modify a minor field like `parameter` in each duplicate
{% endstep %}

{% step %}
Send all modified requests simultaneously (parallel execution)
{% endstep %}

{% step %}
Check if multiple successful transactions occur for the same action
{% endstep %}
{% endstepper %}

***

#### Quota‑Limit Bypass via Concurrent Folder‑Creation Requests

{% stepper %}
{% step %}
Navigate to the Knowledge section on `<platform>` and select a specific `<knowledge_space>` (e.g., project or team space)
{% endstep %}

{% step %}
Create folders until you reach the configured limit `<max_folder_count>` (e.g., 10 folders)
{% endstep %}

{% step %}
Attempt to create one additional folder and confirm the server returns a “limit reached” error
{% endstep %}

{% step %}
Delete one folder so the total count becomes `<max_folder_count - 1>`
{% endstep %}

{% step %}
Immediately after deletion, send `N` parallel folder-creation requests (e.g., 2–20) to `POST <folder_creation_endpoint>` with payloads containing `<folder_name>` (use distinct names for each request)
{% endstep %}

{% step %}
Verify whether the total number of folders for `<knowledge_space>` exceeds `<max_folder_count>`
{% endstep %}
{% endstepper %}

***

#### Non‑Idempotent Request Replay

{% stepper %}
{% step %}
Log in to Account Sign in to the platform using valid credentials
{% endstep %}

{% step %}
Purchase a Gift Card Buy a gift card on the platform
{% endstep %}

{% step %}
Redeem Gift Card Navigate to https://sandbox.reverb.com//redeem and initiate the gift card redemption process
{% endstep %}

{% step %}
Intercept Redemption Request Capture the POST request to /fi/redeem containing utf8, authenticity\_token, token, and commit parameters using Burp Suite Pro
{% endstep %}

{% step %}
Send Request to Turbo Intruder Transfer the intercepted request to Turbo Intruder
{% endstep %}

{% step %}
Set External HTTP Header Configure the external HTTP header x-request: %s in Turbo Intruder
{% endstep %}

{% step %}
Execute the Attack Run the attack in Turbo Intruder and observe multiple 200 OK responses
{% endstep %}

{% step %}
Verify Increased Balance Check the account balance to confirm that the gift card value has been redeemed multiple times
{% endstep %}
{% endstepper %}

***

#### Race Condition (Concurrent Redemption / Double-spend)

{% stepper %}
{% step %}
Log in to Account Sign in to the platform using valid credentials
{% endstep %}

{% step %}
Purchase a Gift Card Buy a gift card on the platform
{% endstep %}

{% step %}
Redeem Gift Card Navigate to https://sandbox.reverb.com//redeem and initiate the gift card redemption process
{% endstep %}

{% step %}
Intercept Redemption Request Capture the POST request to /fi/redeem containing utf8, authenticity\_token, token, and commit parameters using Burp Suite Pro
{% endstep %}

{% step %}
Send Request to Turbo Intruder Transfer the intercepted request to Turbo Intruder and apply the provided Python script with 30 concurrent connections
{% endstep %}

{% step %}
Set External HTTP Header Configure the external HTTP header x-request: %s in Turbo Intruder
{% endstep %}

{% step %}
Execute the Attack Run the attack in Turbo Intruder and observe multiple 200 OK responses
{% endstep %}

{% step %}
Verify Increased Balance Check the account balance to confirm that the gift card value has been redeemed multiple times
{% endstep %}
{% endstepper %}

***

#### Authentication Token Issuance Race

{% stepper %}
{% step %}
Prepare a list of login payloads (include incorrect passwords and the correct password)
{% endstep %}

{% step %}
Choose concurrency level (start with 20–50 parallel requests)
{% endstep %}

{% step %}
Capture a valid login POST request and send it to Burp/Turbo Intruder or a parallel-request tool
{% endstep %}

{% step %}
Configure the tool to send your prepared payloads simultaneously
{% endstep %}

{% step %}
Launch the parallel attack
{% endstep %}

{% step %}
Inspect responses and identify any response that returns a JWT
{% endstep %}

{% step %}
Decode the JWT and extract the authCode (or equivalent MFA state)
{% endstep %}

{% step %}
Construct a login/verify request using the captured JWT and a random 6-digit OTP
{% endstep %}

{% step %}
Send the verify request and check for successful authentication (session or 200 OK)
{% endstep %}

{% step %}
Repeat attempts as needed (race is probabilistic) and log successful JWTs/responses
{% endstep %}
{% endstepper %}

***

#### Email‑verification race

{% stepper %}
{% step %}
Create a new account (email remains unverified)
{% endstep %}

{% step %}
Find and capture the email verification POST request (the one sent when clicking the verification link)
{% endstep %}

{% step %}
Find and capture the change-email request (the POST that updates the account email)
{% endstep %}

{% step %}
Prepare two requests: (A) change-email → set target email (e.g. [victim@domain.com](mailto:victim@domain.com)), (B) verify-email → same valid verification token
{% endstep %}

{% step %}
Use a parallel-request tool (Turbo Intruder / Burp / parallel curl) to send A and B simultaneously (high concurrency / single-packet timing)
{% endstep %}

{% step %}
Inspect responses for success; check the account’s email status
{% endstep %}

{% step %}
Confirm by performing an action that requires a verified email (invite, access feature, etc)
{% endstep %}

{% step %}
Repeat to verify reproducibility and log any successful attempts
{% endstep %}
{% endstepper %}

***

### White Box
