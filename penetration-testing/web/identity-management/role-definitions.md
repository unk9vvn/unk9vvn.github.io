# Role Definitions

## Check List

* [ ] Identify and document roles used by the application.
* [ ] Attempt to switch, change, or access another role.
* [ ] Review the granularity of the roles and the needs behind the permissions given.

## Methodology&#x20;

### Black Box

#### Role Definitions Discovery

{% stepper %}
{% step %}
Identify User Roles and Access Levels Determine the lowest user role in the system (Contributor, Basic User) and understand its permissions and restrictions The goal is to exploit the system using only this minimal privilege account Use this cheat sheet to find account types and Fuzz directories
{% endstep %}

{% step %}
Discover Administrative or Role-Management APIs To find API paths in the system, we can use this Reconnaissance Section cheat sheet in the API Endpoints section use the documentation of that system to find the API paths and roles in the API, And find the API documentation for that site or company Go to their official website and check if they have a developer's section Look for links to API documentation or API references If they don't have a section specifically for developers, try searching their website for 'API', and use this cheat sheet to find API documentation
{% endstep %}

{% step %}
Look for API endpoints that manage user roles or permissions, such as those that update user profiles or change roles These endpoints often use HTTP methods like `PUT`, `PATCH`, or `POST`
{% endstep %}

{% step %}
Test Access Control on These APIs Send requests to these sensitive APIs using a low-privilege account Check if the server properly verifies whether the requesting user has permission to perform the action If the server does not enforce strict authorization checks, the API is vulnerable
{% endstep %}

{% step %}
Retrieve Required Tokens (`CSRF Tokens, Auth Tokens`)  Most APIs require security tokens to prevent unauthorized requests First, make a GET request to fetch the user profile or session data to extract tokens such as CSRF tokens and user IDs
{% endstep %}

{% step %}
Construct the Exploit Request Using the retrieved tokens, craft an HTTP request (typically `PUT` or `PATCH`) to change the user’s role from low privilege to a higher privilege role (such as Administrator) Include all necessary headers such as `X-Csrf-Token and Content-Type: application/json`Prepare the request body (JSON) with the updated role information
{% endstep %}

{% step %}
The attacker logs in using a low-privileged account Now check the API documentation for routes that include IDs They discover an API endpoint like

```
/api/w/{workspace-id}/assistant/conversations/{conversation-id}
```
{% endstep %}

{% step %}
Read Other Users’ Data By changing the conversation ID, they can view other users’ (including admin) conversations: Using different methods (PUT, PATCH , DELETE) We are investigating whether we can use different HTTP methods to influence sensitive API paths that contain IDs and thereby gain unauthorized access To test in Burp, we take the request and change the desired method
{% endstep %}
{% endstepper %}

***

#### Role Parameter Tampering

{% stepper %}
{% step %}
First, let's check what roles are on the site and how they are written (Admin or admin or Administrator and ...) so that you can use this cheat sheet to find the different levels in the system
{% endstep %}

{% step %}
go to sign up page and intercept registration process with burp suite
{% endstep %}

{% step %}
look at registration request body, it can be like this

```json
{
    "username": "USERNAME",
    "name": "$NAME",
    "email": "$EMAIL",
    "phone": "$NUMBER",
    "password": "$PASS",
    "role": "User"
}
```
{% endstep %}

{% step %}
change `User` role to `Admin` role and register. if you can access admin panel, you are an admin If the user id was used with ID instead of role, can we change it and cause account takeover? Instead of role, the registration form may have a numeric `user_type` and by changing that number, we can access Admin or higher roles
{% endstep %}
{% endstepper %}

***

#### Broken Access Control

{% stepper %}
{% step %}
First, enter online shopping or selling sites
{% endstep %}

{% step %}
Ask yourself: Are there higher roles on this site? If so, how can we identify them? The first type (Vertical Privilege Escalation) This means that a regular user can achieve a higher level of access, such as admin. For example, a user who only needs to make purchases can now manage the entire site The second type (Horizontal Privilege Escalation) This means that a user can access the information or capabilities of another user at the same privilege level. For example, a regular buyer can log in to another buyer's account

{% hint style="info" %}
We need to know that there are two main types of access escalation
{% endhint %}
{% endstep %}

{% step %}
Next, find all the sensitive JavaScript files using the Reconnaissance Section in cheat sheet we can reach them
{% endstep %}

{% step %}
The next step is to look for sensitive and suspicious parameters in sensitive JavaScript files, especially those that end with an ID or number, and look for sensitive role words such as (admin, author) and higher roles
{% endstep %}

{% step %}
Find the suspicious route and make a request to the endpoint and intercept the request using burp suite
{% endstep %}

{% step %}
Send the request to the endpoint using the method that is sending the request
{% endstep %}

{% step %}
If there is no response from the request, we change the method to PATCH and resend the request
{% endstep %}
{% endstepper %}

***

#### Role-Based Access Control Bypass

{% stepper %}
{% step %}
First, enter the site, log in, and go to the home page or your account page
{% endstep %}

{% step %}
Right-click on the page, select 'Inspect,' then go to the Network tab and refresh
{% endstep %}

{% step %}
Examine the submitted and loaded requests and consider the endpoints or APIs that contain information about roles, such as role ID or role name. However, role IDs may be numeric rather than textual, so pay attention to this
{% endstep %}

{% step %}
Run the Burp Suite tool and capture the requests, refresh the page, and forward them one by one until you reach the sensitive endpoint
{% endstep %}

{% step %}
In the Burp tool, right-click on the request page and click "Do intercept > Response to this request" to see the response to the request
{% endstep %}

{% step %}
Take the response you received, change the parameters related to the role to higher roles If we gain admin access, the site is vulnerable
{% endstep %}
{% endstepper %}

***

#### JWT/Token Response Manipulation

{% stepper %}
{% step %}
First, enter the registration page of the site
{% endstep %}

{% step %}
Prepare two different accounts for testing. The first account will be used for successful login tests and the second account will be used for unsuccessful login tests and response manipulation
{% endstep %}

{% step %}
Using the Burp Suite tool, intercept the successful login request (with the correct password) and save the response body (like this response) in a designated section

```json
HTTP/1.1 200 OK
Set-Cookie: jwt=...
{"isSuccess":true,
   "token":"<jwt_token>",
   "user":{
   "id":331,
   "email":"acc1@example.com",
   "isAdmin":false,
   "isSecurityAdmin":false
 }}
```
{% endstep %}

{% step %}
Again, using the Burp Suite tool, intercept the failed login request (with the wrong password) and replace the response with the successful login response that you saved. Also change the ID password to that of our first account

```json
HTTP/1.1 200 OK
Set-Cookie: jwt=...
{"isSuccess":true,
   "token":"<jwt_token>",
   "user":{
   "id":332,
   "email":"acc1@example.com",
   "isAdmin":false,
   "isSecurityAdmin":false
 }}
```
{% endstep %}

{% step %}
But the most important thing is that in the response body it shows two words isAdmin which is equal to False and isSecurityAdmin which is also equal to False. And when you inject the successful response body into the unsuccessful response, you can change these two options to True and you can access higher roles like this

```json
HTTP/1.1 200 OK
Set-Cookie: jwt=...
{"isSuccess":true,
   "token":"<jwt_token>",
   "user":{
   "id":331,
   "email":"acc1@example.com",
   "isAdmin":true,
   "isSecurityAdmin":true
 }}
```
{% endstep %}
{% endstepper %}

***

#### **Privilege Escalation Via Role Parameter Tampering**

{% stepper %}
{% step %}
In the systems we are examining, which may contain multiple roles such as user, employee, and admin, what is important is that we can focus on the intermediate roles because they are usually where the errors occur

{% hint style="info" %}
Important note: In some systems, only the admin can convert a regular user to an admin, and intermediate roles such as managers cannot do this
{% endhint %}
{% endstep %}

{% step %}
.In these systems, this scenario should be considered so that we can convert normal users to admins using intermediate accounts and intercept normal user editing requests by managers or intermediate roles using the Burp Suite tool
{% endstep %}

{% step %}
First of all, log in to the admin account, make an edit request on a regular user to make it an admin, and use the Burp Suite tool to track the request. Store suspicious parameters that are used and sent in the request to convert a regular user to an admin in a field, for example, <sub>"\[permissions]=administrator</sub>"
{% endstep %}

{% step %}
The next step is to log in to the intermediate accounts (manager) and request an edit of a regular user in the Burp Suite tool, then add the parameters that were suspicious in the request to convert the regular user to an admin like this

```http
POST /hi/org-url-id/human_resources/user-id HTTP/2
Host: $WEBSITE
Cookie: []
X-Csrf-Token: []
...

_method=patch&
resource_instance[resource_type_id]=[]]&
resource_instance[account_membership_attributes][attach_user]=true&
resource_instance[account_membership_attributes][permissions]=administrator&
resource_instance[account_membership_attributes][add_own_time_off]=0&
resource_instance[account_membership_attributes][schedule]=view&
resource_instance[account_membership_attributes][booking_rights]=manage_own&
resource_instance[account_membership_attributes][downtime_rights]=manage_own&
resource_instance[account_membership_attributes][resource_rights]=manage_own&
resource_instance[account_membership_attributes][project_rights]=manage_own&
resource_instance[account_membership_attributes][client_rights]=manage_own&
resource_instance[account_membership_attributes][report_rights]=view&
resource_instance[account_membership_attributes][id]=386353

```
{% endstep %}

{% step %}
Send a request and check if the normal user has become an admin. If so, there is a vulnerability
{% endstep %}
{% endstepper %}

***

#### Bypass Broken Function Level Authorization

{% stepper %}
{% step %}
Note: Sometimes what we see on the front end may be completely different from what we see on the back end, like in this scenario Perform the registration process within the system with the lowest access level
{% endstep %}

{% step %}
Inside the user account, look for sections that are specific to the admin, such as sections like "Member Rule"
{% endstep %}

{% step %}
When you click on this section, it displays messages such as "Access Denied"

{% hint style="info" %}
But the point is that you shouldn't trust what you are shown and the front end may be misleading
{% endhint %}
{% endstep %}

{% step %}
In this section, use the Burp Suite tool to intercept requests to access areas that are for admins and are not accessible to regular users In the response, you may receive all the information about that section or the users But what if there were no sections like "Member Role"? There are still APIs that expose us to this vulnerability In this section, you can use the documentation from that organization, system, or site to examine APIs and find sensitive paths Finding sensitive JavaScript files and sensitive paths Using Burp tools like Logger and using the Network tab in DevTools to find APIs and routes like

```json
/v1/users
/v1/account/members
/api/roles
/api/users/123/permissions
/api/org/{orgId}/members
/graphql?query={roles,permissions}
/users/{id}/edit
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

### Roles Identification

#### [FFUF](https://github.com/ffuf/ffuf)

#### Hidden Directories

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano hidden-dir-files.sh
```

```bash
#!/bin/bash
​
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <WEBSITE>"
    exit 1
fi
​
WEBSITE="$1"
​
# Validate URL format
if ! [[ "$WEBSITE" =~ ^https?:// ]]; then
    echo "Error: WEBSITE must start with http:// or https://"
    exit 1
fi
​
# Create temporary files
COOKIE_FILE=$(mktemp)
​
# Cleanup function
cleanup()
{
    rm -f "$COOKIE_FILE"
}
trap cleanup EXIT
​
# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)
​
# Extract cookies
COOKIES=$(curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' | awk -F';' '{print $1}' | tr '\n' '; ' | sed 's/; $//')
​
# Append cookies if available
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
fi
​
# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

echo "[+] Scanning directories on $WEBSITE"
ffuf -u "$WEBSITE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt \
     -c -mc 200 \
     -o /tmp/dirs.txt -of json \
     "${HEADER_PARAMS[@]}"

echo "[+] Extracting found directories"
DIRS=$(jq -r '.results[].input.FUZZ' dirs.txt)

for dir in $DIRS; do
    echo "[+] Scanning files in $dir"
    ffuf -u "$WEBSITE/$dir/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt \
    -c -mc 200 \
    "${HEADER_PARAMS[@]}"
done
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x hidden-dir-files.sh;sudo ./hidden-dir-files.sh $WEBSITE
```

#### Cookie and Account

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano cookie-account-identify.sh
```

```bash
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <WEBSITE>"
    exit 1
fi

WEBSITE="$1"

# Validate URL format
if ! [[ "$WEBSITE" =~ ^https?:// ]]; then
    echo "Error: WEBSITE must start with http:// or https://"
    exit 1
fi

# Create temporary files
COOKIE_FILE=$(mktemp)

# Cleanup function
cleanup()
{
    /usr/bin/rm -f "$COOKIE_FILE"
}
trap cleanup EXIT

# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)

# Extract cookies
COOKIES=$(curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' | awk -F';' '{print $1}' | tr '\n' '; ' | sed 's/; $//')

# Function to analyze cookies for sensitive parameters
analyze_cookies()
{
    local COOKIE_PARAMS=($(echo "$COOKIES" | tr ';' '\n' | awk -F'=' '{print $1}'))
    local SENSITIVE_KEYWORDS=("admin" "role" "user" "privilege" "access" "auth" "session" "token" "isAdmin")
    
    for PARAM in "${COOKIE_PARAMS[@]}"; do
        for KEYWORD in "${SENSITIVE_KEYWORDS[@]}"; do
            if [[ "$PARAM" =~ $KEYWORD ]]; then
                echo "Potentially sensitive cookie parameter detected: $PARAM"
            fi
        done
    done
}

# Run cookie analysis
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
    analyze_cookies
fi

# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

# Common user enumeration paths for CMS
CMS_USER_PATHS=(
    "author/FUZZ"  # WordPress
    "user/FUZZ"    # Drupal
)

# Check if paths exist before running ffuf
for PATH in "${CMS_USER_PATHS[@]}"; do
    STATUS_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$WEBSITE/$PATH")
    if [[ "$STATUS_CODE" == "200" ]]; then
        echo "Path exists: $WEBSITE/$PATH - Running ffuf"
        ffuf -w /usr/share/seclists/Usernames/Names/names.txt \
             -u "$WEBSITE/$PATH/FUZZ" \
             -c -mc 200 \
             "${HEADER_PARAMS[@]}"
    else
        echo "Skipping $WEBSITE/$PATH - Not Found"
    fi
    sleep 1 # Prevent too many requests in a short time
done
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x cookie-account-identify.sh;sudo ./cookie-account-identify.sh $WEBSITE
```
