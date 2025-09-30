# Insecure Direct Object References

## Check List



## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
Create two accounts if possible or else enumerate users first.
{% endstep %}

{% step %}
Check if the endpoint is private or public and does it contains any kind of id param.


{% endstep %}

{% step %}
Try changing the param value to some other user and see if does anything to their account
{% endstep %}

{% step %}
change HTTP method like this

<pre class="language-http"><code class="lang-http"><strong>GET /users/delete/victim_id -> 403
</strong>POST /users/delete/victim_id -> 200
</code></pre>
{% endstep %}

{% step %}
Try replacing parameter names instead of this :&#x20;

```http
GET /api/albums?album_id= <album id>
```
{% endstep %}

{% step %}
Try This:

{% hint style="info" %}
Tip: There is a Burp extension called Paramalyzer which\
will help with this by remembering all the parameters you have passed to a host.
{% endhint %}

```http
GET /api/albums?account_id= <account id>
```
{% endstep %}

{% step %}
Path Traversal IN users Path

if request like this :&#x20;

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
swap non-numeric with numeric id

```http
GET /file?id=90djbkdbkdbd29dd
GET /file?id=302
```
{% endstep %}

{% step %}
Missing Function Level Acess Control and changes Charachter path

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
Never ignore encoded/hashed ID for hashed ID ,create multiple accounts and understand the\
pattern application users to allot an iD&#x20;
{% endstep %}

{% step %}
Bypass object level authorization Add parameter onto the endpoit if not present by defualt

```
GET /api_v1/messages -> 200
GET /api_v1/messages?user_id=victim_uuid -> 200
```
{% endstep %}

{% step %}
HTTP Parameter POllution Give mult value for same parameter

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

{% stepper %}
{% step %}
Log in to your own account in two browsers A and B with User A and User B
{% endstep %}

{% step %}
Create your own \*_Licenses and certifications_ in both the account
{% endstep %}

{% step %}
Create your own \*_Licenses and certifications_ in both the account
{% endstep %}

{% step %}
Now In the body change the **ID** number and you will be able to delete all the **Licenses and certifications** present in HackerOne
{% endstep %}

{% step %}
For now change the ID to the **Licenses and certifications** ID of the Other account and it will be deleted.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Go to the subscribe page and sign up with an email (or create two test emails).
{% endstep %}

{% step %}
Note the subscribe URL: `...?p=subscribe&id=1`.
{% endstep %}

{% step %}
Change `subscribe` → `unsubscribe`: `...?p=unsubscribe&id=1`.
{% endstep %}

{% step %}
In the unsubscribe form enter the target email (for example, the email you previously subscribed with).
{% endstep %}

{% step %}
The page shows “You have been unsubscribed...” and a confirmation email is received.\
(The report indicates this works without CAPTCHA or a confirmation link.)=
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Capture the GraphQL `UpdateCampaign` POST request when editing a campaign (example request sent to `POST /graphql` with JSON body containing `input.campaign_id`).
{% endstep %}

{% step %}
The `campaign_id` is a base64-encoded global id (e.g. `Z2lkOi8vaGFja2Vyb25lL0NhbXBhaWduLzI0NA==` → `gid://hackerone/Campaign/244` when decoded).
{% endstep %}

{% step %}
Change the numeric ID part of the decoded GID (e.g. `244` → `243` or `245`), re‑encode the modified GID to base64 and replace `input.campaign_id` with that value in the same request.
{% endstep %}

{% step %}
Send the modified `UpdateCampaign` request. The server accepts the request for the targeted `campaign_id` (even if that campaign belongs to another program), allowing the campaign to be updated/removed via that request.
{% endstep %}

{% step %}
Impact: by targeting another program’s ongoing campaign id, a requester can modify or delete campaigns they don’t own.

{% hint style="info" %}
Key detail: decode `campaign_id` from base64 → you get `gid://hackerone/Campaign/<N>`. Modifying `<N>` and re-encoding changes the target campaign.\
\
\
idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity_rating`,`readable_substate`,`created_at`,`submitted_at`,`reporter_name`
{% endhint %}
{% endstep %}
{% endstepper %}
