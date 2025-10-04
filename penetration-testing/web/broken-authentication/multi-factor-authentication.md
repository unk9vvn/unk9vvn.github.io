# Multi-Factor Authentication

## Check List



## Cheat Sheet

### Methodology

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

#### **Changing Error Response to Success**

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

### **OTP Bypass Using Form Resubmission in Repeater**

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

### **Bypassing OTP with No Rate Limiting**

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

### **Additional OTP Bypass Test Cases**

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

### **Rate Limiting Attack on OTP Verification**

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
