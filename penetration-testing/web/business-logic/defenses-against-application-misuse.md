# Defenses Against Application Misuse

## Check List

## Methodology

### Black Box

#### Missing Rate Limiting on Login

{% stepper %}
{% step %}
Access the login endpoint
{% endstep %}

{% step %}
Intercept a normal login request

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=WrongPass1
```
{% endstep %}

{% step %}
Send the request to Burp Intruder
{% endstep %}

{% step %}
Set payload position on the password parameter
{% endstep %}

{% step %}
Launch a password brute-force attack with multiple password attempts, Observe server responses
{% endstep %}

{% step %}
If unlimited attempts are allowed without CAPTCHA, delay, or account lockout, rate limiting is absent
{% endstep %}

{% step %}
If no temporary lock or IP block occurs after high number of attempts, misuse protection is missing
{% endstep %}
{% endstepper %}

***

#### No Account Lockout After Failed OTP Attempts

{% stepper %}
{% step %}
Initiate OTP verification process
{% endstep %}

{% step %}
Intercept OTP verification request

```http
POST /api/verify-otp HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"otp":"000000"}
```
{% endstep %}

{% step %}
Send request to Burp Intruder
{% endstep %}

{% step %}
Brute-force OTP values `(000000–999999)`
{% endstep %}

{% step %}
Monitor responses, If unlimited attempts are accepted without invalidation or delay, OTP brute-force protection is missing
{% endstep %}

{% step %}
If OTP remains valid despite multiple failures, application misuse defense is broken
{% endstep %}
{% endstepper %}

***

#### No Rate Limiting on Password Reset

{% stepper %}
{% step %}
Access password reset endpoint, Intercept request

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
{% endstep %}

{% step %}
Send request repeatedly via Burp Intruder
{% endstep %}

{% step %}
Monitor response behavior, If unlimited reset emails are triggered without throttling, email flooding is possible
{% endstep %}

{% step %}
If no CAPTCHA or rate limiting exists, abuse protection is missing
{% endstep %}
{% endstepper %}

***

#### No API Rate Limiting

{% stepper %}
{% step %}
Intercept API request

```http
GET /api/search?q=test HTTP/1.1
Host: target.com
Authorization: Bearer token123
```
{% endstep %}

{% step %}
Send request to Burp Intruder or Turbo Intruder
{% endstep %}

{% step %}
Increase request rate significantly
{% endstep %}

{% step %}
Monitor response codes, If server consistently returns 200 without 429 (Too Many Requests), API rate limiting is not enforced
{% endstep %}

{% step %}
If high request volume does not trigger blocking or throttling, misuse defense is insufficient
{% endstep %}
{% endstepper %}

***

#### Missing CAPTCHA on Critical Forms

{% stepper %}
{% step %}
Access registration or login page
{% endstep %}

{% step %}
Observe whether CAPTCHA is present, Intercept registration request

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=test@test.com&password=Test123
```
{% endstep %}

{% step %}
Replay multiple automated registration requests
{% endstep %}

{% step %}
If accounts can be created programmatically without CAPTCHA validation or anti-automation control, abuse prevention is absent
{% endstep %}

{% step %}
If no bot mitigation exists on high-risk forms, misuse protection vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
