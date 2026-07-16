# Broken Authentication

## Check List

## Methodology

### Black Box

#### Missing Authentication on Sensitive API Endpoint

{% stepper %}
{% step %}
Do not authenticate to the application
{% endstep %}

{% step %}
Directly access a protected API endpoint

```http
GET /api/user/profile HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response returns user data without requiring Authorization header, authentication enforcement is missing
{% endstep %}

{% step %}
Test with random token

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer randomtoken123
```
{% endstep %}

{% step %}
If endpoint responds with valid user data or default user context, authentication validation is broken
{% endstep %}

{% step %}
If no 401/403 response is returned for unauthenticated access, Broken Authentication is confirmed
{% endstep %}
{% endstepper %}

***

#### Predictable JWT Secret

{% stepper %}
{% step %}
Login and capture JWT

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```
{% endstep %}

{% step %}
Decode JWT payload, Identify algorithm

```json
{"alg":"HS256"}
```
{% endstep %}

{% step %}
Attempt to brute-force weak secret using jwt tool
{% endstep %}

{% step %}
If secret is guessable (`"secret", "123456"`), generate new token with modified payload:

```json
{"user":"admin","role":"admin"}
```
{% endstep %}

{% step %}
Sign token with discovered secret, Replace Authorization header

```http
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
Access privileged endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
If access is granted, JWT authentication mechanism is broken
{% endstep %}

{% step %}
If server accepts forged token, Broken Authentication vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Session Fixation via API

{% stepper %}
{% step %}
Access login endpoint and intercept response

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"user1","password":"Pass123"}
```
{% endstep %}

{% step %}
Observe returned session token

```http
Set-Cookie: session=abc123; Path=/; HttpOnly
```
{% endstep %}

{% step %}
Before login, manually set session cookie

```http
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Perform login, If server reuses provided session ID after authentication

```http
Set-Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Then session fixation is possible, Use fixed session in another browser

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
If authenticated access is granted, session management is flawed
{% endstep %}

{% step %}
If session ID is not regenerated upon login, Broken Authentication vulnerability is confirmed
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
