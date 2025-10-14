# Weak Username Policy

## Check List

* [ ] Determine whether a consistent account name structure renders the application vulnerable to account enumeration.
* [ ] Determine whether the application’s error messages permit account enumeration.

## Methodology&#x20;

### Black Box

#### Email header injection via CRLF

{% stepper %}
{% step %}
Go to the site’s "Contact Us" section and find the organizational or admin email You can find registered accounts on that site using this script, which is in the cheat sheet
{% endstep %}

{% step %}
Find the registration and login pages and go to the email or password recovery section
{% endstep %}

{% step %}
Capture and track recovery requests using the Burp Suite tool Important note: If the website processes multiple email parameters, you can put our own email next to the registered user's email and recieve the password recovery link or email
{% endstep %}

{% step %}
In the interception of a password recovery request or email, if the request method is POST, as in the following request, add your email next to the test email or the user’s email

```http
GET /password-reset
Host: example.com
SetCookie: $COOKIE

email=user@mail.com%0A%0Dbcc:my@mail.com
```
{% endstep %}

{% step %}
If the request method was sent as GET, then add your email address next to the test email or another user's email address like this

```http
GET /password-reset?email=user@mail.com&email=my@mail.com
Host: example.com
SetCookie: 
```
{% endstep %}

{% step %}
If a recovery link was sent to your email, change your password and BOOOOM, Account Takeover
{% endstep %}
{% endstepper %}

***

#### Password‑reset API bypass

{% stepper %}
{% step %}
In the APIs (documentation and other methods for finding the APIs mentioned in the previous methodologies), you should look for paths related to password recovery, such as the following paths

```json
/api/password-reset
/auth/reset-password
/api/users/reset
/api/forgot-password
/api/change-password
/api/resetpass
```
{% endstep %}

{% step %}
The next step is that once you find these routes, you should note that most of them contain parameters that lead us to vulnerabilities, such as the following parameter present in the requests for these routes

```json
{
  "username/ID/Emali": "",
  "new_password": "new_pass456"
}
```
{% endstep %}

{% step %}
Search for these routes on the site, make requests, and track these requests using the Burp Suite tool
{% endstep %}

{% step %}
The parameters may contain an ID, username, or email. Replace these parameters with the ID, username, or email of the target user and send the request It is better to create a test email for these types of tests and check the test email after each scenario. If it works, you have found the vulnerability
{% endstep %}
{% endstepper %}

***

#### Account enumeration via weak username policy

{% stepper %}
{% step %}
Go to the login page, enter your email and password, and track the request using the Burp Suite tool
{% endstep %}

{% step %}
To find users, test different usernames using cheat sheet scripts If you enter the correct email, the server informs that it exists, but if you enter the wrong email, the server responds by informing that this email does not exist
{% endstep %}

{% step %}
There is a Weak Username Policy vulnerability here
{% endstep %}

{% step %}
The next important step is to enter the forgotten password section and change the request method from POST to GET
{% endstep %}

{% step %}
Change the forgotten password path to `/api/users,`If it shows the records and user information in the response, you have found the vulnerability
{% endstep %}
{% endstepper %}

***

#### **Username enumeration & 2FA bypass via error message differences and JSON response manipulation**

{% stepper %}
{% step %}
First of all, go to the registration section of the site and complete the registration process with two user accounts It is possible that the username automatically created for us in the system may follow a guessable pattern, and you should take this into account
{% endstep %}

{% step %}
For example, a username could be jac1234, and it can be found using brute-force techniques After you understand the username pattern for each account after registration, Start testing the login page to see how the system responds to both unsuccessful and successful logins
{% endstep %}

{% step %}
The next step is to use the Burp Suite tool to track login requests and the response differences between successful and unsuccessful logins
{% endstep %}

{% step %}
If the user is incorrect, the program or system will display `The username is incorrect` but if the username is correct and the password is incorrect, it will display `The password is incorrect` This difference in error messages allows us to perform the username enumeration process by systematically testing different usernames and examining the responses
{% endstep %}

{% step %}
Use the Intruder feature in Burp to automate the process of finding valid usernames and random passwords Important: The intruder payload section uses a common list of usernames to generate possible prefixes (first three letters) And brute-forced the last four digits You can add the phrase 'password is incorrect' to the Grep-Match settings to identify valid usernames based on the error responses
{% endstep %}

{% step %}
Now, using the list of valid usernames, go to the Forgot Password section, use the Burp Suite tool to request a traceback, and send a valid username with an incorrect password for user confirmation
{% endstep %}

{% step %}
Now right-click on the request section and click on the "Response to this request" option so that you can receive the response to our request
{% endstep %}

{% step %}
If the response is in JSON format and the response body contains 'false,' manipulate it and convert it to 'true' If you enter the next stage, change the password and log in to the user account with the new information, and you will find the vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

### Register & Weak Username

[**Katana** ](https://github.com/projectdiscovery/katana)**&** [**cURL**](https://curl.se/) **&** [**WayBackURL**](https://github.com/tomnomnom/waybackurls)**​**

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano sc-weak-username.sh
```

```bash
#!/bin/bash

# --- Colors for better output ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

DOMAIN=$1
[ -z "$DOMAIN" ] && { echo -e "${RED}Usage: $0 <domain.com>${NC}"; exit 1; }

# --- Detect protocol based on open ports ---
echo -e "${BLUE}[*] Detecting protocol for $DOMAIN ...${NC}"
HTTP_OPEN=$(timeout 2 bash -c "</dev/tcp/$DOMAIN/80" && echo "open" || echo "")
HTTPS_OPEN=$(timeout 2 bash -c "</dev/tcp/$DOMAIN/443" && echo "open" || echo "")

if [[ -n "$HTTPS_OPEN" ]]; then
  PROTO="https"
elif [[ -n "$HTTP_OPEN" ]]; then
  PROTO="http"
else
  echo -e "${RED}[-] Neither port 80 nor 443 is open on $DOMAIN. Exiting.${NC}"
  exit 1
fi

echo -e "${GREEN}[+] Using protocol: $PROTO://$DOMAIN${NC}"

# --- Setup output directory ---
OUTDIR="/tmp/register_crawl"
mkdir -p "$OUTDIR"
URL="$PROTO://$DOMAIN"

# --- Clean previous files ---
rm -f "$OUTDIR"/*.txt "$OUTDIR"/*.html

# --- Crawl with katana ---
echo -e "${BLUE}[*] Crawling with katana...${NC}"
katana -u "$URL" -d 3 -jsl -fr -silent -o "$OUTDIR/katana.txt"

# --- Check URL history with waybackurls ---
echo -e "${BLUE}[*] Fetching historical URLs with waybackurls...${NC}"
echo "$DOMAIN" | waybackurls >> "$OUTDIR/wayback.txt"

# --- Add common registration paths ---
echo -e "${BLUE}[*] Adding common registration paths...${NC}"
COMMON_PATHS=(
  "/register" "/signup" "/join" "/create-account" "/new-user" 
  "/registration" "/sign-up" "/onboarding" "/account/create"
  "/account/register" "/users/sign_up" "/users/new"
  "/auth/register" "/auth/signup" "/membership" "/subscribe"
  "/free-trial" "/start" "/begin" "/account/new"
)

for path in "${COMMON_PATHS[@]}"; do
  echo "$PROTO://$DOMAIN$path" >> "$OUTDIR/common_paths.txt"
done

# --- Merge and deduplicate URLs ---
echo -e "${BLUE}[*] Merging and deduplicating URLs...${NC}"
cat "$OUTDIR"/*.txt | sort -u > "$OUTDIR/all_unique.txt"

# --- Filter for accessible HTML pages ---
echo -e "${BLUE}[*] Filtering for accessible HTML pages...${NC}"
cat "$OUTDIR/all_unique.txt" | httpx -silent -mc 200,201,202,203,204,301,302 > "$OUTDIR/accessible_urls.txt"

# --- Filter for potential registration-related URLs ---
echo -e "${BLUE}[*] Filtering for potential registration-related URLs...${NC}"
grep -iE 'signup|register|sign[-_]?up|sign[-_]?in|create[_-]?account|join|new[_-]?user|account|login|auth|user|signup|apply|admission|enroll|membership|subscribe|trial|onboard' "$OUTDIR/accessible_urls.txt" | sort -u > "$OUTDIR/register_candidates.txt"

# --- Add homepage to candidates ---
echo "$URL" >> "$OUTDIR/register_candidates.txt"
cat "$OUTDIR/register_candidates.txt" | sort -u > "$OUTDIR/final_candidates.txt"

if [ ! -s "$OUTDIR/final_candidates.txt" ]; then
  echo -e "${RED}[-] No potential registration paths found.${NC}"
  exit 1
fi

echo -e "${GREEN}[+] Candidate URLs for registration forms:${NC}"
cat "$OUTDIR/final_candidates.txt"

# --- Create directory for found forms ---
FORMS_DIR="$OUTDIR/forms"
mkdir -p "$FORMS_DIR"

# --- Function to check if a form is likely a registration form ---
is_registration_form() {
  local form="$1"
  local score=0

  if echo "$form" | grep -qi "register\|signup\|sign up\|create account\|join"; then ((score+=3)); fi
  if echo "$form" | grep -qi "email\|e-mail"; then ((score+=2)); fi
  if echo "$form" | grep -qi "password"; then ((score+=2)); fi
  if echo "$form" | grep -qi "confirm\|verify\|repeat" && echo "$form" | grep -qi "password"; then ((score+=3)); fi
  if echo "$form" | grep -qi "username\|user name\|login\|account"; then ((score+=2)); fi
  if echo "$form" | grep -qi "name\|first\|last\|full name"; then ((score+=1)); fi
  if echo "$form" | grep -qi "agree\|terms\|policy\|consent"; then ((score+=2)); fi
  if echo "$form" | grep -qi "captcha\|recaptcha\|robot"; then ((score+=1)); fi
  if echo "$form" | grep -qi "phone\|mobile\|sms\|verification"; then ((score+=1)); fi
  if echo "$form" | grep -qi "submit\|register\|signup\|join\|create\|continue"; then ((score+=1)); fi

  if [ $score -ge 5 ]; then return 0; else return 1; fi
}

# --- Check each URL for registration forms ---
echo -e "${BLUE}[*] Checking URLs for registration forms...${NC}"
FOUND_FORMS=0

while read -r url; do
  echo -e "${YELLOW}[~] Checking: $url${NC}"
  html=$(curl -Lks "$url")
  [ -z "$html" ] && { echo -e "${RED}  [-] Failed to fetch content${NC}"; continue; }

  echo "$html" > "$FORMS_DIR/$(echo "$url" | md5sum | cut -d' ' -f1).html"

  echo "$html" | grep -i -o '<form[^>]*method="post"[^>]*>.*</form>' -s | while read -r form; do
    if is_registration_form "$form"; then
      ((FOUND_FORMS++))
      FORM_FILE="$FORMS_DIR/register_form_${FOUND_FORMS}.html"
      echo "$form" > "$FORM_FILE"

      echo -e "\n${GREEN}[✔] Found potential registration form at: $url${NC}"
      echo -e "${BLUE}[*] Form input fields found:${NC}"
      echo "$form" | grep -o '<input[^>]*>' | grep 'name=' | sed 's/^.*name="\([^"]*\)".*$/- \1/' | sort -u

      echo -e "${GREEN}[+] Saved form HTML to: $FORM_FILE${NC}"
    fi
  done
done < "$OUTDIR/final_candidates.txt"

# --- SIMULATE registration request ---
echo -e "${BLUE}[*] Simulating registration and saving response...${NC}"
curl -X POST "$URL/register" \
  -d "username=johnsmith123&email=john@example.com&password=Passw0rd!" \
  -s -k -L -o "$OUTDIR/register_response.html"

echo -e "${GREEN}[+] Registration response saved to: $OUTDIR/register_response.html${NC}"

# --- Extract username from response (example: JSON or HTML) ---
echo -e "${BLUE}[*] Extracting username from response...${NC}"
USERNAME=""
# If JSON:
if grep -q '"username"' "$OUTDIR/register_response.html"; then
  USERNAME=$(grep -oP '"username"\s*:\s*"\K[^"]+' "$OUTDIR/register_response.html")
else
  USERNAME=$(grep -oP '(?<=class="username">)[^<]+' "$OUTDIR/register_response.html")
fi

echo -e "${GREEN}[+] Extracted username: $USERNAME${NC}"

# --- Analyze username weakness ---
analyze_username() {
  local username="$1"
  local first_name="$2"
  local last_name="$3"
  local issues=0

  echo -e "${BLUE}[*] Analyzing username: $username${NC}"

  if [[ "$username" == *"$first_name"* ]]; then
    echo -e "${YELLOW}[!] Username contains first name: $first_name${NC}"
    ((issues++))
  fi

  if [[ "$username" == *"$last_name"* ]]; then
    echo -e "${YELLOW}[!] Username contains last name: $last_name${NC}"
    ((issues++))
  fi

  if [[ "$username" =~ [0-9]{2,} ]]; then
    echo -e "${YELLOW}[!] Username contains obvious numbers: ${BASH_REMATCH[0]}${NC}"
    ((issues++))
  fi

  if [ ${#username} -lt 5 ]; then
    echo -e "${YELLOW}[!] Username is very short (less than 5 chars)${NC}"
    ((issues++))
  fi

  if [[ "$username" =~ [^a-zA-Z0-9._-] ]]; then
    echo -e "${YELLOW}[!] Username contains unusual characters${NC}"
    ((issues++))
  fi

  if [ $issues -eq 0 ]; then
    echo -e "${GREEN}[+] Username seems strong${NC}"
  else
    echo -e "${RED}[-] Detected $issues potential weakness(es) in username${NC}"
  fi
}

FIRST_NAME="john"
LAST_NAME="smith"
analyze_username "$USERNAME" "$FIRST_NAME" "$LAST_NAME"

echo -e "${GREEN}[✔] Done!${NC}"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x sc-weak-username.sh;sudo ./sc-weak-username.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
