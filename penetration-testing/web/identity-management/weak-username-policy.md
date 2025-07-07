# Weak Username Policy

## Check List

* [ ] _Determine whether a consistent account name structure renders the application vulnerable to account enumeration._
* [ ] _Determine whether the application’s error messages permit account enumeration._

## Cheat Sheet

### Register & Weak Username

[**Katana** ](https://github.com/projectdiscovery/katana)**&** [**cURL**](https://curl.se/) **&** [**WayBackURL**](https://github.com/tomnomnom/waybackurls)**​**

_Create Script_

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

_Run Script_

```bash
sudo chmod +x sc-weak-username.sh;sudo ./sc-weak-username.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
