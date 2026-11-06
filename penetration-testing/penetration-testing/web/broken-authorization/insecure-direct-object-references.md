# Insecure Direct Object References

## Check List

## Methodology

### Black Box

#### HTTP Methods

{% stepper %}
{% step %}
Log in to the target site and track requests using the Burp Suite tool
{% endstep %}

{% step %}
Complete the authentication process then log in to your profile
{% endstep %}

{% step %}
Perform a process that deletes a photo or account. Trace the request using Burp suite
{% endstep %}

{% step %}
After intercepting the request, check if there is a number in the request that means the user ID, then change it to another account
{% endstep %}

{% step %}
After changing the request, check the server response and see if it is 403 or 404
{% endstep %}

{% step %}
If it gives 404 or 403 then change the method if it is POST to GET and if it is GET to POST like the following request

```http
GET /users/delete/victim_id -> 403
POST /users/delete/victim_id -> 200
```
{% endstep %}

{% step %}
Try This

{% hint style="info" %}
Tip: There is a Burp extension called Paramalyzer which\
will help with this by remembering all the parameters you have passed to a host
{% endhint %}
{% endstep %}

{% step %}
#### Path Traversal IN users Path

Register two accounts, one in the attacker's name in the Firefox browser and the other in the victim's name using the Chrome browser on the target page
{% endstep %}

{% step %}
Create both accounts and log in to the profile page, then click Delete Account with the attacker's account and track the request using the Burp Suite tool
{% endstep %}

{% step %}
Then check if there is an id or number inside the request that indicates the user account id. If there is, change the id to the victim account that we created with the Chrome browser and check the server response to see if it is 403 or not

```http
POST /users/delete/victim_id -> 403
```
{% endstep %}

{% step %}
If it does not allow, we replace the path traversal payload with something like the following request

```http
POST /users/delete/my_id/..victim_id -> 200
```
{% endstep %}
{% endstepper %}

***

#### [Missing Function Level Acess Control and changes Charachter path](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References#wildcard-parameter)

{% stepper %}
{% step %}
Reconcile the target site using the complete [cheat sheet](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications)
{% endstep %}

{% step %}
Then look for sensitive paths like admin paths
{% endstep %}

{% step %}
Send the request to this route and check if the server response is incoming or returns 401

```http
GET /admin/profile -> 401
```
{% endstep %}

{% step %}
Then change the admin request to uppercase like the following request and check if the server allows us to log in. If it does, the vulnerability is confirmed

```http
GET /Admin/profile -> 200
GET /ADMIN/profile -> 200
```
{% endstep %}
{% endstepper %}

***

#### Objected JSON Parameter

{% stepper %}
{% step %}
Complete the authentication process on the target site
{% endstep %}

{% step %}
Log in to your profile and go to the profile settings section
{% endstep %}

{% step %}
Make a change to your profile. Trace the request using Burp suite before hitting the save button
{% endstep %}

{% step %}
Then click the save button and check whether the request you received is in json format or not
{% endstep %}

{% step %}
Identify the userid parameter inside it, change it, and check if the server gives you a 403 or not

```json
{"userid":123} -> 401
```
{% endstep %}

{% step %}
If it gives an error, send the request as a JSON object, like the following request

```json
{"userid":{"userid":123}} -> 200
```
{% endstep %}
{% endstepper %}

***

#### [Using the \* character instead of the user ID](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References#wildcard-parameter)

{% stepper %}
{% step %}
Log into the target site and intercept requests using the Burp suite tool
{% endstep %}

{% step %}
Then identify the requests related to the user's API routes, such as the following route request

```http
GET /api/users/user_id 
```
{% endstep %}

{% step %}
Then change the request for the user `id` in the user path to `*` and check if the server accepts it or not

```http
GET /api/users/*
```
{% endstep %}

{% step %}
If it shows user information after sending the request, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### [JSON Parameter Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References#idor-tips)

{% stepper %}
{% step %}
Log in to the target site and complete the authentication process
{% endstep %}

{% step %}
Then register. After registration, log out
{% endstep %}

{% step %}
Then go to Login and enter the correct username and password. Then use the Burp suite tool to intercept the requests and click the Login button
{% endstep %}

{% step %}
Get the login request. If the userid exists, change it to another id. Check whether you are logging into another account or not

```json
{"userid":123} -> 401
```
{% endstep %}

{% step %}
If you are not logged into another user account, repeat the login process and instead of changing the id in the parameters similar to userid, convert it to an array as follows

```json
{"userid":[123]} -> 200
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

#### Access to Unpublished

{% stepper %}
{% step %}
Create an account on the target platform
{% endstep %}

{% step %}
Create at least two blog posts:

* One published/public
* One unpublished or set as “Private” / “Draft” / “Hidden”
{% endstep %}

{% step %}
While creating or editing the private post, intercept all requests with Burp Suite
{% endstep %}

{% step %}
Identify the endpoint that loads a single post, usually one of these patterns

```hurl
/post/123  
/api/posts/123  
/blog/view?id=123  
/api/v1/articles/123  
/content/123
```
{% endstep %}

{% step %}
Note the numeric or alphanumeric ID of your public post and your private post
{% endstep %}

{% step %}
Log out or open an incognito window (or use a second account that should NOT have access)
{% endstep %}

{% step %}
Manually send a direct request to the private post ID like&#x20;

```hurl
https://weblog-builder.target.com/post/456
```
{% endstep %}

{% step %}
If the full private post content loads → vulnerability confirmed
{% endstep %}
{% endstepper %}

***

#### IDOR In Reset Password Functionality

{% stepper %}
{% step %}
Log in to the target site then use 2 accounts
{% endstep %}

{% step %}
One account is `attacker@gmail.com` and the other is `vitcim@gmail.com`, which takes us to the forgotten password page
{% endstep %}

{% step %}
With the second account, `vitcim@gmail.com`, we complete the forgotten password process, then after changing the password, we check whether the link has been used and whether it can be used again
{% endstep %}

{% step %}
Then check the link to see if there is any base64 encoded data at the end or middle of the URL. If there is, decode it
{% endstep %}

{% step %}
Then check if your userid and gmail show in decrypted mode
{% endstep %}

{% step %}
If it shows, then enter the email and userid of the first account, that is, `attacker@gmail.com`, and use the link again. Then, after completing the forgotten password process, check whether the user's email password has been changed on the site. If it has been changed, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Attachment Download Endpoint Leading IDOR

{% stepper %}
{% step %}
Create two user accounts with different privilege levels (for example, one authorized user and one restricted user)
{% endstep %}

{% step %}
Identify a feature that allows users to upload, view, or download attachment files
{% endstep %}

{% step %}
Using the authorized user account, upload a file or locate an existing attachment
{% endstep %}

{% step %}
While viewing or downloading the attachment, monitor the network traffic

```http
GET /api/attachments/12345/download HTTP/1.1
Cookie: session=authorized_user
```
{% endstep %}

{% step %}
Identify the API endpoint responsible for serving the file
{% endstep %}

{% step %}
Capture the request and send it to Burp Repeater
{% endstep %}

{% step %}
Log in with the low-privileged account that should not have access to the target resource
{% endstep %}

{% step %}
Replay the file download request using the low-privileged user's session

```http
GET /api/attachments/12345/download HTTP/1.1
Cookie: session=low_priv_user
```
{% endstep %}

{% step %}
Check whether the server returns the file or responds with an authorization error
{% endstep %}

{% step %}
If the file is successfully returned, verify that the low-privileged user cannot access the same resource through the user interface (UI)
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass Through Exposed Object Identifiers

{% stepper %}
{% step %}
Create two user accounts with separate ownership contexts (an attacker account and a victim account)
{% endstep %}

{% step %}
Using the attacker account, create a resource on which sensitive actions such as editing, publishing, deleting, previewing, or administration can be performed
{% endstep %}

{% step %}
Intercept all requests generated while interacting with this resource
{% endstep %}

{% step %}
Identify the primary identifier used in sensitive operations (such as `resourceId`, `projectId`, `websiteId`, `pageId`, or similar values)

```http
POST /api/projects/123/publish HTTP/1.1
Host: target.com
Cookie: session=attacker

{
  "projectId": "123"
}
```
{% endstep %}

{% step %}
Send the request to Burp Repeater and determine whether the sensitive operation is performed solely based on the identifier supplied by the user
{% endstep %}

{% step %}
Select a state-changing operation such as delete, edit, publish, or archive
{% endstep %}

{% step %}
Replace the resource identifier with the identifier of another resource and inspect the server response

```http
POST /api/projects/456/publish HTTP/1.1
Host: target.com
Cookie: session=attacker

{
  "projectId": "456"
}
```
{% endstep %}

{% step %}
If the operation succeeds, investigate how the target identifier is exposed
{% endstep %}

{% step %}
Analyze all API responses, network requests, DOM elements, JavaScript variables, and HTML attributes to identify the required identifiers
{% endstep %}

{% step %}
Extract any secondary identifiers used in the operation (such as `componentId`, `widgetId`, `blockId`, or similar values) and determine their sourc

```http
POST /api/projects/456/components/789/delete HTTP/1.1
Host: target.com
Cookie: session=attacker

{
  "projectId": "456",
  "componentId": "789"
}
```
{% endstep %}

{% step %}
Using the extracted identifiers, send the sensitive request against a resource owned by another user
{% endstep %}

{% step %}
Verify whether the server validates resource ownership or simply trusts the provided identifiers
{% endstep %}

{% step %}
Confirm that the operation succeeds despite the absence of administrative privileges over the target resource
{% endstep %}
{% endstepper %}

***

### White Box

#### IDOR via Authorization-Result Cache Poisoning in a Cross-Request Object Loader

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
Identify whether the API exposes a GraphQL endpoint, or any REST handler that resolves objects by ID through a batching/loader abstraction designed to avoid N+1 database queries, and test whether per-object ownership is enforced consistently by requesting an object you do not own and observing the exact failure behavior
{% endstep %}

{% step %}
In the decompiled code, locate the resolver/handler for the object-fetch field and trace how it retrieves data for a given ID — specifically whether it delegates to a loader/batcher component rather than querying the repository directly inline
{% endstep %}

{% step %}
Determine the lifetime and scope of that loader/batcher instance: is a fresh instance constructed for every incoming HTTP request (correct, since its internal cache then dies with the request), or is it registered as an application-wide singleton / static field / module-level constant shared across every concurrent request the process ever handles (incorrect)
{% endstep %}

{% step %}
Locate the authorization check that is supposed to verify the requesting user owns the object, and determine precisely when it executes relative to the loader's own cache lookup — does it run unconditionally every single time `load(id)` is called, or does the surrounding code explicitly skip it when the loader reports (or the code infers) that the ID was "already loaded" during this process's lifetime
{% endstep %}

{% step %}
Check the exact order of operations inside the handler: does the loader populate its shared cache with the row _before_ the ownership check runs and potentially rejects the request — if so, the row is already cached and globally retrievable the instant the underlying database fetch succeeds, regardless of whether the very same request is ultimately denied

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(static readonly ConcurrentDictionary)|(loader\.WasCached\()|(!wasCached)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@Scope\(\s*\"singleton\"\s*\))|(\.wasCached\()|(!wasCached)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(private static array \$cache)|(->wasCached\()|(!\$wasCached)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(const cache = new Map\(\))|(cache\.has\(id\))|(!wasCached)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
static readonly ConcurrentDictionary|loader\.WasCached\(|!wasCached
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Scope\(\s*"singleton"\s*\)|\.wasCached\(|!wasCached
```
{% endtab %}

{% tab title="PHP" %}
```regexp
private static array \$cache|->wasCached\(|!\$wasCached
```
{% endtab %}

{% tab title="Node.js" %}
```regex
const cache = new Map\(\)|cache\.has\(id\)|!wasCached
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public class DocumentLoader // [1] registered in DI as a singleton, shared across every request the process handles
{
    private static readonly ConcurrentDictionary<string, Document> _cache = new(); // [2] keyed only by document id, no user/request scope

    public Document Load(string id)
    {
        if (_cache.TryGetValue(id, out var cached))
            return cached; // cache hit, returned as-is

        var doc = _repository.GetById(id);
        _cache[id] = doc; // [3] cached before any authorization decision has been made
        return doc;
    }

    public bool WasCached(string id) => _cache.ContainsKey(id);
}

[GraphQLField]
public Document GetDocument(string id, [Service] DocumentLoader loader, ClaimsPrincipal user)
{
    var wasCached = loader.WasCached(id); // [4] cache-hit state captured before the ownership check
    var doc = loader.Load(id);

    if (!wasCached) // [5] ownership is only ever verified the first time anyone, in any request, loads this id
    {
        if (doc.OwnerId != user.GetUserId())
            throw new UnauthorizedAccessException();
    }

    return doc;
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
@Scope("singleton") // [1] one instance shared across every request the process handles
public class DocumentLoader {
    private final ConcurrentHashMap<String, Document> cache = new ConcurrentHashMap<>(); // [2] keyed only by document id, no user/request scope

    public Document load(String id) {
        Document cached = cache.get(id);
        if (cached != null) return cached; // cache hit, returned as-is

        Document doc = repository.getById(id);
        cache.put(id, doc); // [3] cached before any authorization decision has been made
        return doc;
    }

    public boolean wasCached(String id) {
        return cache.containsKey(id);
    }
}

public Document getDocument(String id, Authentication auth) {
    boolean wasCached = documentLoader.wasCached(id); // [4] cache-hit state captured before the ownership check
    Document doc = documentLoader.load(id);

    if (!wasCached) { // [5] ownership is only ever verified the first time anyone, in any request, loads this id
        if (!doc.getOwnerId().equals(getUserId(auth))) {
            throw new AccessDeniedException("Forbidden");
        }
    }

    return doc;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DocumentLoader {
    // [1] constructed once and reused across requests by the persistent worker runtime (e.g. Swoole / RoadRunner)
    private static array $cache = []; // [2] keyed only by document id, no user/request scope

    public function load(string $id): Document {
        if (isset(self::$cache[$id])) {
            return self::$cache[$id]; // cache hit, returned as-is
        }

        $doc = DocumentRepository::getById($id);
        self::$cache[$id] = $doc; // [3] cached before any authorization decision has been made
        return $doc;
    }

    public function wasCached(string $id): bool {
        return isset(self::$cache[$id]);
    }
}

function getDocument(string $id, $loader, $user) {
    $wasCached = $loader->wasCached($id); // [4] cache-hit state captured before the ownership check
    $doc = $loader->load($id);

    if (!$wasCached) { // [5] ownership is only ever verified the first time anyone, in any request, loads this id
        if ($doc->ownerId !== $user->id) {
            throw new ForbiddenException();
        }
    }

    return $doc;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
// [1] created once at module load time and reused by every request the process handles
const cache = new Map(); // [2] keyed only by document id, no user/request scope

async function loadDocument(id) {
  if (cache.has(id)) {
    return cache.get(id); // cache hit, returned as-is
  }

  const doc = await documentRepository.getById(id);
  cache.set(id, doc); // [3] cached before any authorization decision has been made
  return doc;
}

async function getDocument(id, user) {
  const wasCached = cache.has(id); // [4] cache-hit state captured before the ownership check
  const doc = await loadDocument(id);

  if (!wasCached) { // [5] ownership is only ever verified the first time anyone, in any request, loads this id
    if (doc.ownerId !== user.id) {
      throw new ForbiddenError();
    }
  }

  return doc;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the loader is a process-wide singleton, not a per-request object, `[2]` its cache key carries no notion of who is asking, `[3]` the row is written into that shared cache before the function even reaches the authorization decision, `[4]`/`[5]` the ownership check is gated entirely on whether this exact ID has ever been loaded before by anyone, anywhere, in the lifetime of the process — once that's true, the check never runs again
{% endstep %}

{% step %}
Request an object ID you do not own exactly once. The first response is correctly denied — but the row was already written into the shared cache by `Load()`/`load()` before the denial was thrown

```http
POST /graphql HTTP/1.1
Host: target.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"query":"query { document(id: \"a1b2c3-victim-doc\") { id title body } }"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"errors":[{"message":"Forbidden"}]}
```
{% endstep %}

{% step %}
Replay the exact same request a second time. The loader now reports a cache hit for that ID, the ownership check from step 9 is skipped entirely, and the object is returned in full

```http
POST /graphql HTTP/1.1
Host: target.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"query":"query { document(id: \"a1b2c3-victim-doc\") { id title body } }"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"data":{"document":{"id":"a1b2c3-victim-doc","title":"Q3 Board Resolution","body":"..."}}}
```
{% endstep %}

{% step %}
If the second, byte-for-byte identical request succeeds where the first one was correctly denied, the authorization check has been permanently disabled for that object ID for every user on the process — including, but not limited to, the attacker — confirming a self-triggerable, persistent cross-user IDOR with no victim interaction required
{% endstep %}
{% endstepper %}

***

#### IDOR via Internal Object-Reference Leakage to a Downstream Microservice That Skips Its Own Ownership Check

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
Identify whether the application uses opaque references (UUIDs, random tokens) for objects in its public-facing API while internally using sequential numeric primary keys, and locate the translation/lookup layer that resolves one into the other
{% endstep %}

{% step %}
In the decompiled code, confirm that the ownership/ACL check is performed exactly once, at this translation step, and trace every downstream service call that receives the already-resolved internal numeric ID afterward
{% endstep %}

{% step %}
For each downstream service found (export/render workers, webhook delivery, thumbnail/notification pipelines, audit pipelines), determine whether that service independently re-validates ownership of the internal ID it receives, or whether it implicitly trusts that only the gateway/translation layer could ever have produced a legitimate ID
{% endstep %}

{% step %}
Determine whether any of those downstream services exposes an endpoint reachable directly — a separate internal subdomain that is nonetheless internet-routable, a status-polling endpoint the frontend JavaScript calls directly rather than through the gateway, or a webhook callback URL
{% endstep %}

{% step %}
Trigger a normal, fully authorized action on any object you legitimately own (an export, a render job, a share) while capturing every outbound network request the client makes, and check whether the internal numeric ID is exposed anywhere in that traffic — a status-poll URL, a generated file's embedded metadata, a webhook payload
{% endstep %}

{% step %}
Once the internal ID's format and rough numeric range are known, call the downstream service's directly reachable endpoint with a different internal ID that belongs to an object you do not own, bypassing the opaque-reference translation layer and its ownership check entirely

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(GetByInternalId\()|(exports/\{internalId)|(internal\.target\.tld)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(getByInternalId\()|(\"/exports/\{internalId)|(internal\.target\.tld)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(getByInternalId\()|(/exports/.*internalId)|(internal\.target\.tld)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(getByInternalId\()|(/exports/:internalId)|(internal\.target\.tld)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
GetByInternalId\(|exports/\{internalId|internal\.target\.tld
```
{% endtab %}

{% tab title="Java" %}
```regexp
getByInternalId\(|"/exports/\{internalId|internal\.target\.tld
```
{% endtab %}

{% tab title="PHP" %}
```regexp
getByInternalId\(|/exports/.*internalId|internal\.target\.tld
```
{% endtab %}

{% tab title="Node.js" %}
```regex
getByInternalId\(|/exports/:internalId|internal\.target\.tld
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost("documents/{publicRef}/export")]
[Authorize]
public IActionResult StartExport(string publicRef)
{
    var internalId = _refTranslator.Resolve(publicRef); // [1] the only place the opaque reference is ever translated
    var doc = _documentRepository.GetByInternalId(internalId);

    if (doc.OwnerId != User.GetUserId()) // [2] ownership correctly checked here, exactly once
        return Forbid();

    _exportService.StartExport(internalId);
    return Ok(new { statusUrl = $"https://export.internal.target.tld/exports/{internalId}/status" }); // [3] the internal id is handed straight to the client
}

// On a completely separate, directly internet-reachable service:
[HttpGet("exports/{internalId:long}/status")]
public IActionResult GetExportStatus(long internalId) // [4] no [Authorize] attribute, no caller-identity check at all
{
    var job = _exportRepository.GetByInternalId(internalId); // [5] fetched purely by the numeric id, no owner comparison anywhere
    if (job == null) return NotFound();

    return Ok(new { status = job.Status, downloadUrl = job.ResultUrl });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/documents/{publicRef}/export")
@Secured("ROLE_USER")
public ResponseEntity<?> startExport(@PathVariable String publicRef, Authentication auth) {
    long internalId = refTranslator.resolve(publicRef); // [1] the only place the opaque reference is ever translated
    Document doc = documentRepository.getByInternalId(internalId);

    if (!doc.getOwnerId().equals(getUserId(auth))) { // [2] ownership correctly checked here, exactly once
        return ResponseEntity.status(403).build();
    }

    exportService.startExport(internalId);
    return ResponseEntity.ok(Map.of("statusUrl",
        "https://export.internal.target.tld/exports/" + internalId + "/status")); // [3] the internal id is handed straight to the client
}

// On a completely separate, directly internet-reachable service:
@GetMapping("/exports/{internalId}/status")
public ResponseEntity<?> getExportStatus(@PathVariable long internalId) { // [4] no security annotation, no caller-identity check at all
    ExportJob job = exportRepository.getByInternalId(internalId); // [5] fetched purely by the numeric id, no owner comparison anywhere
    if (job == null) return ResponseEntity.notFound().build();

    return ResponseEntity.ok(Map.of("status", job.getStatus(), "downloadUrl", job.getResultUrl()));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function startExport($publicRef, $user) {
    $internalId = RefTranslator::resolve($publicRef); // [1] the only place the opaque reference is ever translated
    $doc = DocumentRepository::getByInternalId($internalId);

    if ($doc->ownerId !== $user->id) { // [2] ownership correctly checked here, exactly once
        http_response_code(403);
        return;
    }

    ExportService::startExport($internalId);
    echo json_encode([
        'statusUrl' => "https://export.internal.target.tld/exports/$internalId/status" // [3] the internal id is handed straight to the client
    ]);
}

// On a completely separate, directly internet-reachable service:
function getExportStatus($internalId) { // [4] no auth middleware on this route, no caller-identity check at all
    $job = ExportRepository::getByInternalId($internalId); // [5] fetched purely by the numeric id, no owner comparison anywhere
    if ($job === null) {
        http_response_code(404);
        return;
    }

    echo json_encode(['status' => $job->status, 'downloadUrl' => $job->resultUrl]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post('/documents/:publicRef/export', requireAuth, async (req, res) => {
  const internalId = await refTranslator.resolve(req.params.publicRef); // [1] the only place the opaque reference is ever translated
  const doc = await documentRepository.getByInternalId(internalId);

  if (doc.ownerId !== req.user.id) { // [2] ownership correctly checked here, exactly once
    return res.status(403).end();
  }

  await exportService.startExport(internalId);
  res.json({ statusUrl: `https://export.internal.target.tld/exports/${internalId}/status` }); // [3] the internal id is handed straight to the client
});

// On a completely separate, directly internet-reachable service:
app.get('/exports/:internalId/status', async (req, res) => { // [4] no auth middleware on this route, no caller-identity check at all
  const job = await exportRepository.getByInternalId(req.params.internalId); // [5] fetched purely by the numeric id, no owner comparison anywhere
  if (!job) return res.status(404).end();

  res.json({ status: job.status, downloadUrl: job.resultUrl });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]`/`[2]` the public-facing gateway does the right thing — it resolves the opaque reference and checks ownership exactly once, `[3]` it then hands the now-bare internal ID directly to the client as part of a status URL, `[4]`/`[5]` the service on the other end of that URL has no idea who is calling it and performs no ownership check of its own, because it was designed under the assumption that only the gateway, which already checked, would ever address it
{% endstep %}

{% step %}
Start an export on any document you legitimately own and capture the status URL the client receives

```http
POST /documents/3f29ac10-44f1/export HTTP/1.1
Host: target.tld
Authorization: Bearer <attacker-token>
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"statusUrl":"https://export.internal.target.tld/exports/8841/status"}
```
{% endstep %}

{% step %}
Address the downstream service directly with a neighboring internal ID, with no token, gateway, or ownership context of any kind

```http
GET /exports/8840/status HTTP/1.1
Host: export.internal.target.tld
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"completed","downloadUrl":"https://cdn.target.tld/exports/8840/invoice.pdf"}
```
{% endstep %}

{% step %}
Download the resulting file and confirm it belongs to a different account/tenant entirely. If so, the opaque-reference layer that the public API relies on for authorization has been fully bypassed simply by addressing the same data through a different, unauthenticated door
{% endstep %}
{% endstepper %}

***

#### IDOR via Polymorphic Resource-Type Confusion in a Shared Generic Permission Table

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
Identify whether the application stores access grants, shares, comments, or attachments for many unrelated object types in a single shared table using a generic polymorphic pattern — a `resource_id` (numeric) column paired with a `resource_type` (string) discriminator column — rather than dedicated per-type tables or real foreign-key constraints
{% endstep %}

{% step %}
In the decompiled code, locate the single, generic permission-check helper used across multiple object types (commonly named something like `canAccess(resourceType, resourceId, userId)`) and inspect the exact query it builds against the shared polymorphic table
{% endstep %}

{% step %}
Determine whether that query actually filters on the `resource_type` discriminator column, or whether — due to a refactor, an incomplete migration from an earlier non-polymorphic schema, or a copy-pasted single-argument overload — it filters only by `resource_id`, treating the type argument as informational and never including it in the `WHERE` clause
{% endstep %}

{% step %}
Confirm whether IDs across different object types can independently collide — most ORMs default to a separate auto-increment sequence per table, meaning two completely unrelated object types (e.g. `Comment` and `Invoice`) can legitimately reach the exact same numeric ID at roughly the same point in the application's history
{% endstep %}

{% step %}
Identify, or deliberately create, a low-sensitivity object of a type you are legitimately granted access to whose numeric ID matches the numeric ID of a sensitive object of a different type that you are not authorized to view
{% endstep %}

{% step %}
Request the sensitive object's endpoint, supplying its real type discriminator but relying on the colliding numeric ID — the permission helper's query matches your own grant record, which was recorded under the unrelated type, because the type was never part of the comparison

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(CanAccess\()|(FROM OwnableResources WHERE ResourceId)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(canAccess\()|(findByResourceIdAndUserId)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(canAccess\()|(where\('resource_id')
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(canAccess\()|(resource_id:\s*resourceId)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
CanAccess\(|FROM OwnableResources WHERE ResourceId
```
{% endtab %}

{% tab title="Java" %}
```regexp
canAccess\(|findByResourceIdAndUserId
```
{% endtab %}

{% tab title="PHP" %}
```regexp
canAccess\(|where\('resource_id'
```
{% endtab %}

{% tab title="Node.js" %}
```regex
canAccess\(|resource_id:\s*resourceId
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public bool CanAccess(string resourceType, long resourceId, long userId)
{
    // [1] resourceType is accepted as a parameter but never referenced below
    var grant = _db.OwnableResources
        .FirstOrDefault(r => r.ResourceId == resourceId && r.UserId == userId); // [2] missing `&& r.ResourceType == resourceType`

    return grant != null;
}

[HttpGet("invoices/{id}")]
public IActionResult GetInvoice(long id)
{
    if (!_permissions.CanAccess("Invoice", id, User.GetUserId())) // [3] type passed in good faith, silently discarded downstream
        return Forbid();

    return Ok(_invoiceRepository.GetById(id));
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean canAccess(String resourceType, long resourceId, long userId) {
    // [1] resourceType is accepted as a parameter but never referenced below
    OwnableResource grant = ownableResourceRepository
        .findByResourceIdAndUserId(resourceId, userId); // [2] missing a resourceType filter

    return grant != null;
}

@GetMapping("/invoices/{id}")
public ResponseEntity<?> getInvoice(@PathVariable long id, Authentication auth) {
    if (!permissions.canAccess("Invoice", id, getUserId(auth))) { // [3] type passed in good faith, silently discarded downstream
        return ResponseEntity.status(403).build();
    }

    return ResponseEntity.ok(invoiceRepository.getById(id));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function canAccess($resourceType, $resourceId, $userId) {
    // [1] $resourceType is accepted as a parameter but never referenced below
    $grant = OwnableResource::where('resource_id', $resourceId) // [2] missing ->where('resource_type', $resourceType)
        ->where('user_id', $userId)
        ->first();

    return $grant !== null;
}

function getInvoice($id) {
    if (!canAccess('Invoice', $id, currentUserId())) { // [3] type passed in good faith, silently discarded downstream
        http_response_code(403);
        return;
    }

    echo json_encode(InvoiceRepository::getById($id));
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
async function canAccess(resourceType, resourceId, userId) {
  // [1] resourceType is accepted as a parameter but never referenced below
  const grant = await db('ownable_resources')
    .where({ resource_id: resourceId, user_id: userId }) // [2] missing resource_type in the filter
    .first();

  return !!grant;
}

app.get('/invoices/:id', async (req, res) => {
  const allowed = await canAccess('Invoice', req.params.id, req.user.id); // [3] type passed in good faith, silently discarded downstream
  if (!allowed) return res.status(403).end();

  res.json(await invoiceRepository.getById(req.params.id));
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the function signature suggests it discriminates by type, `[2]` the actual query never does, `[3]` every caller across the codebase passes the type in good faith, unaware that it is discarded the moment it reaches the shared helper — meaning a grant recorded for _any_ object type satisfies the check for _every_ object type, as long as the numeric ID matches
{% endstep %}

{% step %}
Create or comment on any low-sensitivity object you are legitimately allowed to access, and note the numeric ID assigned to your own grant record

```http
POST /posts/55/comments HTTP/1.1
Host: target.tld
Authorization: Bearer <low-priv-token>
Content-Type: application/json

{"body":"nice post"}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"id":4192,"body":"nice post"}
```
{% endstep %}

{% step %}
Request the sensitive, unrelated endpoint using that exact numeric ID under its real type discriminator

```http
GET /invoices/4192 HTTP/1.1
Host: target.tld
Authorization: Bearer <low-priv-token>
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":4192,"customer":"Acme Holdings","amount":"48250.00","lineItems":[{"description":"Annual support contract","total":"48250.00"}]}
```
{% endstep %}

{% step %}
If an invoice belonging to a completely different company is returned, the permission check is confirmed to have matched on the numeric ID alone — your own, unrelated comment grant for the same ID was sufficient to pass an authorization check for an entirely different object type that you were never granted access to
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
