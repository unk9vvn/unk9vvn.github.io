# Weak Security Question Answer

## Check List

## Methodology

### Black Box

#### Bypass Security Question Answer

{% stepper %}
{% step %}
Navigate to the target application’s account registration page
{% endstep %}

{% step %}
Create a new user account and observe the security question setup process
{% endstep %}

{% step %}
Capture the list of **pre-generated security questions** presented to the user
{% endstep %}

{% step %}
Document all available questions and analyze whether they fall into weak categories such as: Publicly discoverable information (e.g., favorite movie, date of birth) or Easily guessable answers (e.g., favorite color)
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Navigate to the **Forgot Password** or account recovery functionality
{% endstep %}

{% step %}
Initiate a password reset request for the created account
{% endstep %}

{% step %}
Observe how many security questions must be answered (one or multiple)
{% endstep %}

{% step %}
Attempt to answer the security questions using: Publicly available information (e.g., search engines, social media) or Common wordlists for brute-force attempts
{% endstep %}

{% step %}
Monitor the application’s behavior when submitting incorrect answers: Check whether unlimited attempts are allowed
{% endstep %}

{% step %}
If the application allows **self-generated security questions**, configure custom questions during account setup
{% endstep %}

{% step %}
Create weak or trivial self-generated questions (e.g., simple math, username-based, or password-revealing questions)
{% endstep %}

{% step %}
Trigger the password recovery process and confirm that the system uses the weak self-generated questions for verification
{% endstep %}

{% step %}
Attempt to enumerate usernames and retrieve associated security questions (if possible)
{% endstep %}

{% step %}
Confirm whether weak security questions and/or insufficient brute-force protections allow bypass of the password reset mechanism
{% endstep %}

{% step %}
Verify that successful guessing of security question answers results in unauthorized password reset capability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
