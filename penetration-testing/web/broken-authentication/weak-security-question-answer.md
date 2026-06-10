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

#### Weak Security Question Verification Leading to Account Recovery Bypass

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all paths related to Login
{% endstep %}

{% step %}
In the source code, locate the Controller or Service responsible for account recovery and analyze the full request flow from user input to access issuance

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("api/account/recovery")]
public IActionResult RecoverAccount(RecoveryRequest request)
{
    var user = _userService.FindByEmail(request.Email);

    if (user == null)
        return NotFound();

    var isAnswerValid = _securityService.VerifySecurityAnswer(
        user.Id,
        request.SecurityAnswer
    );

    if (!isAnswerValid)
        return Unauthorized();

    var token = _tokenService.GenerateRecoveryToken(user.Id);

    return Ok(new { recoveryToken = token });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("api/account/recovery")
public Object RecoverAccount(RecoveryRequest request)
{
    User user = _userService.findByEmail(request.getEmail());

    if (user == null)
        return NotFound();

    boolean isAnswerValid = _securityService.verifySecurityAnswer(
        user.getId(),
        request.getSecurityAnswer()
    );

    if (!isAnswerValid)
        return Unauthorized();

    String token = _tokenService.generateRecoveryToken(user.getId());

    return Ok(Map.of("recoveryToken", token));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost("api/account/recovery")]
public function RecoverAccount(RecoveryRequest $request)
{
    $user = $this->_userService->FindByEmail($request->Email);

    if ($user == null)
        return NotFound();

    $isAnswerValid = $this->_securityService->VerifySecurityAnswer(
        $user->Id,
        $request->SecurityAnswer
    );

    if (!$isAnswerValid)
        return Unauthorized();

    $token = $this->_tokenService->GenerateRecoveryToken($user->Id);

    return Ok(["recoveryToken" => $token]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post("/api/account/recovery", (request, response) => {
    const user = _userService.findByEmail(request.body.Email);

    if (user == null)
        return NotFound();

    const isAnswerValid = _securityService.verifySecurityAnswer(
        user.Id,
        request.body.SecurityAnswer
    );

    if (!isAnswerValid)
        return Unauthorized();

    const token = _tokenService.generateRecoveryToken(user.Id);

    return Ok({ recoveryToken: token });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then inspect the Security Question validation logic in the Service layer and determine whether comparison is performed in a weak way (direct comparison, no hashing, no salt, or no rate limiting)

{% tabs %}
{% tab title="C#" %}
```csharp
public bool VerifySecurityAnswer(int userId, string answer)
{
    var storedAnswer = _repository.GetSecurityAnswer(userId);

    return storedAnswer == answer;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean verifySecurityAnswer(int userId, String answer)
{
    String storedAnswer = _repository.getSecurityAnswer(userId);

    return storedAnswer.equals(answer);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function VerifySecurityAnswer(int $userId, string $answer)
{
    $storedAnswer = $this->_repository->GetSecurityAnswer($userId);

    return $storedAnswer == $answer;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function verifySecurityAnswer(userId, answer)
{
    const storedAnswer = _repository.getSecurityAnswer(userId);

    return storedAnswer == answer;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Trace how the security question answer is stored and verify whether it is stored in plaintext or in an insecure and predictable format

{% tabs %}
{% tab title="C#" %}
```csharp
public void SetSecurityQuestion(int userId, string answer)
{
    _context.SecurityQuestions.Add(new SecurityQuestion
    {
        UserId = userId,
        Answer = answer
    });

    _context.SaveChanges();
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void setSecurityQuestion(int userId, String answer)
{
    _context.getSecurityQuestions().add(new SecurityQuestion(
        userId,
        answer
    ));

    _context.saveChanges();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function SetSecurityQuestion(int $userId, string $answer)
{
    $this->_context->SecurityQuestions->add(new SecurityQuestion([
        "UserId" => $userId,
        "Answer" => $answer
    ]));

    $this->_context->saveChanges();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function setSecurityQuestion(userId, answer)
{
    _context.SecurityQuestions.push({
        UserId: userId,
        Answer: answer
    });

    _context.saveChanges();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Follow the full authentication recovery flow and determine whether successful security question validation directly leads to token issuance or account access without requiring the original password

{% tabs %}
{% tab title="C#" %}
```csharp
var recoveryToken = _tokenService.GenerateRecoveryToken(user.Id);

var accessToken = _authService.ExchangeRecoveryTokenForAccessToken(recoveryToken);

return Ok(new { accessToken });
```
{% endtab %}

{% tab title="Java" %}
```java
String recoveryToken = _tokenService.generateRecoveryToken(user.getId());

String accessToken = _authService.exchangeRecoveryTokenForAccessToken(recoveryToken);

return Ok(Map.of("accessToken", accessToken));
```
{% endtab %}

{% tab title="PHP" %}
```php
$recoveryToken = $this->_tokenService->GenerateRecoveryToken($user->Id);

$accessToken = $this->_authService->ExchangeRecoveryTokenForAccessToken($recoveryToken);

return Ok(["accessToken" => $accessToken]);
```
{% endtab %}

{% tab title="Node.js" %}
```js
const recoveryToken = _tokenService.generateRecoveryToken(user.Id);

const accessToken = _authService.exchangeRecoveryTokenForAccessToken(recoveryToken);

return Ok({ accessToken });
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether the security question answer is normalized or sanitized before comparison, or if it is directly compared without proper validation

{% tabs %}
{% tab title="C#" %}
```csharp
var normalizedAnswer = request.SecurityAnswer.Trim().ToLower();

var isValid = user.SecurityAnswer == normalizedAnswer;
```
{% endtab %}

{% tab title="Java" %}
```java
String normalizedAnswer = request.getSecurityAnswer().trim().toLowerCase();

boolean isValid = user.getSecurityAnswer().equals(normalizedAnswer);
```
{% endtab %}

{% tab title="PHP" %}
```php
$normalizedAnswer = strtolower(trim($request->SecurityAnswer));

$isValid = $user->SecurityAnswer == $normalizedAnswer;
```
{% endtab %}

{% tab title="Node.js" %}
```js
const normalizedAnswer = request.body.SecurityAnswer.trim().toLowerCase();

const isValid = user.SecurityAnswer == normalizedAnswer;
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then verify whether brute-force attacks are possible against the security question and whether protections such as rate limiting, account lockout, or anomaly detection exist

{% tabs %}
{% tab title="C#" %}
```csharp
if (_rateLimiter.IsBlocked(request.Ip))
{
    return StatusCode(429);
}
```
{% endtab %}

{% tab title="Java" %}
```java
if (_rateLimiter.isBlocked(request.getIp()))
{
    return StatusCode(429);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if ($this->_rateLimiter->IsBlocked($request->Ip))
{
    return StatusCode(429);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
if (_rateLimiter.isBlocked(request.ip))
{
    return StatusCode(429);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Finally, analyze the full flow from email input → recovery request → security question response → token generation → account access, and determine whether weak security question logic can lead to Account Takeover
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
