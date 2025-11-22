# Insecure Direct Object References

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References#idor-tips)

{% stepper %}
{% step %}
Create two accounts if possible or else enumerate users first
{% endstep %}

{% step %}
Check if the endpoint is private or public and does it contains any kind of id param
{% endstep %}

{% step %}
Try changing the param value to some other user and see if does anything to their account
{% endstep %}

{% step %}
change HTTP method like this

```http
GET /users/delete/victim_id -> 403
POST /users/delete/victim_id -> 200
```
{% endstep %}

{% step %}
Try replacing parameter names instead of this

```http
GET /api/albums?album_id= <album id>
```
{% endstep %}

{% step %}
Try This

{% hint style="info" %}
Tip: There is a Burp extension called Paramalyzer which\
will help with this by remembering all the parameters you have passed to a host
{% endhint %}

```http
GET /api/albums?account_id= <account id>
```
{% endstep %}

{% step %}
#### Path Traversal IN users Path

if request like this

```http
POST /users/delete/victim_id -> 403
```
{% endstep %}

{% step %}
change request to this&#x20;

```http
POST /users/delete/my_id/..victim_id -> 200
```
{% endstep %}

{% step %}
change request content-type

```http
Content-Type: application/xml
Content-Type: application/json
```
{% endstep %}

{% step %}
#### swap non-numeric with numeric id

```http
GET /file?id=90djbkdbkdbd29dd
GET /file?id=302
```
{% endstep %}

{% step %}
#### [Missing Function Level Acess Control and changes Charachter path](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References#wildcard-parameter)

```
GET /admin/profile -> 401
GET /Admin/profile -> 200
GET /ADMIN/profile -> 200
```
{% endstep %}

{% step %}
send wildcard instead of an id

```http
GET /api/users/user_id 
changes to this
GET /api/users/*
```
{% endstep %}

{% step %}
Never ignore encoded/hashed ID for hashed ID ,create multiple accounts and understand the pattern application users to allot an iD&#x20;
{% endstep %}

{% step %}
Bypass object level authorization Add parameter onto the endpoit if not present by defualt

```
GET /api_v1/messages -> 200
GET /api_v1/messages?user_id=victim_uuid -> 200
```
{% endstep %}

{% step %}
HTTP Parameter Pollution Give mult value for same parameter

```http
GET /api_v1/messages?user_id=attacker_id&user_id=victim_id
GET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```
{% endstep %}

{% step %}
change file type

```http
GET /user_data/2341 -> 401
GET /user_data/2341.json -> 200
GET /user_data/2341.xml -> 200
GET /user_data/2341.config -> 200
GET /user_data/2341.txt -> 200
```
{% endstep %}

{% step %}
json parameter pollution

```json
{"userid":1234,"userid":2542}
```
{% endstep %}

{% step %}
Wrap the ID with an array in the body

```json
{"userid":123} -> 401
{"userid":[123]} -> 200
```
{% endstep %}

{% step %}
c wrap the id with a json objec

```json
{"userid":123} -> 401
{"userid":{"userid":123}} -> 200
```
{% endstep %}

{% step %}
Test an outdata API version

```http
GET /v3/users_data/1234 -> 401
GET /v1/users_data/1234 -> 200
```
{% endstep %}
{% endstepper %}

***

#### Delete Account (IDOR)

{% stepper %}
{% step %}
Log in to your own account in two browsers A and B with User A and User B
{% endstep %}

{% step %}
Create your own \*Licenses and certifications in both the account
{% endstep %}

{% step %}
Create your own \*Licenses and certifications in both the account
{% endstep %}

{% step %}
Now In the body change the **ID** number and you will be able to delete all the **Licenses and certifications** present in HackerOne
{% endstep %}

{% step %}
For now change the ID to the **Licenses and certifications** ID of the Other account and it will be deleted.
{% endstep %}
{% endstepper %}

***

#### Unsubscribe IDOR

{% stepper %}
{% step %}
Go to the subscribe page and sign up with an email (or create two test emails)
{% endstep %}

{% step %}
Note the subscribe URL: `...?p=subscribe&id=`
{% endstep %}

{% step %}
Change subscribe → unsubscribe: `...?p=unsubscribe&id=1`
{% endstep %}

{% step %}
In the unsubscribe form enter the target email (for example, the email you previously subscribed with)
{% endstep %}

{% step %}
The page shows “You have been unsubscribed...” and a confirmation email is received\
(The report indicates this works without <sub>CAPTCHA</sub> or a confirmation link)
{% endstep %}
{% endstepper %}

***

#### GraphQL IDOR

{% stepper %}
{% step %}
Capture the GraphQL `UpdateCampaign` POST request when editing a campaign (example request sent to `POST /graphql` with JSON body containing `input.campaign_id`)
{% endstep %}

{% step %}
The `campaign_id` is a base64-encoded global id (e.g. `Z2lkOi8vaGFja2Vyb25lL0NhbXBhaWduLzI0NA==` → `gid://hackerone/Campaign/244` when decoded)
{% endstep %}

{% step %}
Change the numeric ID part of the decoded GID (e.g. `244` → `243` or `245`), re‑encode the modified GID to base64 and replace `input.campaign_id` with that value in the same request
{% endstep %}

{% step %}
Send the modified `UpdateCampaign` request. The server accepts the request for the targeted `campaign_id` (even if that campaign belongs to another program), allowing the campaign to be updated/removed via that request
{% endstep %}

{% step %}
Impact: by targeting another program’s ongoing campaign id, a requester can modify or delete campaigns they don’t own

{% hint style="info" %}
Key detail: decode `campaign_id` from base64 → you get `gid://hackerone/Campaign/<N>`Modifying `<N>` and re-encoding changes the target campaign.\
\
\
idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity_rating`,`readable_substate`,`created_at`,`submitted_at`,`reporter_name`
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### Account Deletion IDOR

{% stepper %}
{% step %}
Create two test accounts: `victim@test` and `attacker@test`. Ensure you control both
{% endstep %}

{% step %}
From the victim account, initiate an account-delete flow in your browser while intercepting requests (Burp/DevTools) to capture the JSON body that would be sent (this reveals the body format; do **not** forward the request). Example body contains `email` and `authPW`
{% endstep %}

{% step %}
Cancel the actual request so no deletion occurs
{% endstep %}

{% step %}
Log in as attacker and prepare a new `POST /v1/account/destroy` request in an interceptor/repeater. Replace the body with the victim’s captured `email` and `authPW` values (only for your test accounts). **Send the request only if both accounts are test accounts you control**
{% endstep %}

{% step %}
Observe server response: if the server returns success and the victim account is deleted, the vulnerability is confirmed. Prefer to confirm by checking server response codes and deletion flags rather than deleting real production data
{% endstep %}
{% endstepper %}

***

#### GraphQL IDOR

{% stepper %}
{% step %}
allows to modify the links of any user. Users can put their custom links or social media links on their profile&#x20;
{% endstep %}

{% step %}
Replicate the following request by replacing it with your own authentication headers
{% endstep %}

{% step %}
must also put in the body of the request, in the parameter "username" the username that you want, you can try my username: "criptexhackerone1". This request will return in the response the links of any user profile with the "id" of each link. for example

```json
POST / HTTP/2
Host: gql.example.com

{"id":"11a239b07f86","variables":{"username":"*********"}}
```
{% endstep %}

{% step %}
When you get some "id" save it
{% endstep %}

{% step %}
In the next request you have to put in the request body, in the "id" parameter the previously saved id, you can also change the name and the link

```json
POST / HTTP/2
Host: gql.example.com

{"id":"c558e604581f","variables":{"input":{"socialLinks":[{"outboundUrl":"https://www.hackerone.com","title":"hacker","type":"CUSTOM","id":"* * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *"}]}}}
```
{% endstep %}

{% step %}
Finally re-enter the victim's profile and you will see the modified links. It is important to mention that you may have to reload the page a few times or wait a few seconds

{% hint style="info" %}
A real attacker can modify the name and content of any user's social links. It is important to add that social links are something main in user profiles, if an attacker exploits this with all reddit users it could be devastating
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### IDOR Broken Object Level Authorization

{% stepper %}
{% step %}
Login (attacker)**:** Authenticate in the application with your test attacker account in a browser
{% endstep %}

{% step %}
Capture baseline request: Navigate to the profile endpoint and capture the request to

```http
GET /api/v1/users/current? HTTP/1.1
```
{% endstep %}

{% step %}
Prepare modified request: In Repeater, modify the request path by replacing `current?` with a target identifier

```http
GET /api/v1/users/$USERNAME HTTP/1.1
```
{% endstep %}

{% step %}
Send modified reques&#x74;**:** Send it from Repeater and inspect the HTTP response body

{% hint style="info" %}
If the response returns JSON containing the target’s profile fields (e.g., `full_name`, `username`, `github_username`, `website`, `created_at`, `id`, `photo`, etc.), the endpoint leaks other users’ data
{% endhint %}
{% endstep %}

{% step %}
Verify with controlled accounts (recommended): For a safe PoC, create a second test account (victim-test), add a distinguishable field (e.g., `bio: "victim-test-proof"`), then repeat step 3 using that username — this proves read access without touching real users
{% endstep %}

{% step %}
Document evidence: Save/sanitize the HTTP request and response (redact cookies, Authorization headers, tokens and any PII you don’t own). Take a screenshot of the returned JSON (with sensitive fields redacted if needed). Note timestamps and user-agents
{% endstep %}

{% step %}
Do not brute-force: Avoid enumerating many usernames or automating tests on production. Limit yourself to 1–2 manual checks or use staging
{% endstep %}
{% endstepper %}

***

#### Content Move IDOR

{% stepper %}
{% step %}
You can move your contents via <sub>Move to</sub> button at $WEB/dashboard&#x20;
{% endstep %}

{% step %}
when you click to Move to > My Content you will send a POST request to `/dashboard` like that
{% endstep %}

{% step %}
<sub>$ACTIONABLE\[]</sub> parameter's value is the content's ID. And if you change this ID to victim's content ID, you will see victim's content at My Content page
{% endstep %}

{% step %}
After sending the request through Burp Suite and changing the parameter, go back to the Mycontent section
{% endstep %}
{% endstepper %}

***

#### Featured Image Deletion IDOR

{% stepper %}
{% step %}
Make two accounts one is for the victim and the other for an attacker
{% endstep %}

{% step %}
Add some featured images in both accounts. Go to Profile --> Add Profile Section --> Recommended --> Add Featured
{% endstep %}

{% step %}
Delete an image on the attacker's account and capture that request using burp and sent it to the repeater It makes a delete request like the one, given below
{% endstep %}

{% step %}
It takes consists of thress things ProfileId, and sectionUrn which also take same ProfileId value
{% endstep %}

{% step %}
Now visit the victim's profile featured images without logging in as the victim. Copy the link of the image you want to delete from the victim's profile, which looks like this
{% endstep %}

{% step %}
Paste that link into your notepad and notice that in this link, we got both ProfileId , ImageId.\
In the above link, I get these
{% endstep %}

{% step %}
Now simply replace the respected values of required parameters in the repeater and send a request
{% endstep %}

{% step %}
You see that the targeted featured image from the victim's profile was successfully deleted
{% endstep %}
{% endstepper %}

***

#### IDOR in Update Profile Section

{% stepper %}
{% step %}
create An Account in web and go to Update Profile Section For example

```url
https://example.com/UpdateProfile/<user-id>
```
{% endstep %}

{% step %}
Change the Numeric <sub>user-id</sub> to any other, and you'll see other user's email-addresses
{% endstep %}
{% endstepper %}

***

#### File Download IDOR

{% stepper %}
{% step %}
Go to the site and wherever you see CSV file download and other extensions, activate the Interception section using Burp Suite
{% endstep %}

{% step %}
Click on download file and get the request
{% endstep %}

{% step %}
In the request, look for a parameter that has the word ID or is numeric
{% endstep %}

{% step %}
Manipulate the parameter and change the Id and send the response
{% endstep %}

{% step %}
If another file with other content including user information or sensitive information is found inside this downloaded file, it has IDOR vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
