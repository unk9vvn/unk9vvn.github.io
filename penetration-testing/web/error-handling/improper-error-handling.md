# Improper Error Handling

## Check List

## Methodology

### Black Box

#### Improper Error Handling Leading to Information Disclosure

{% stepper %}
{% step %}
Navigate to the target web application and identify accessible API endpoints
{% endstep %}

{% step %}
Interact with the API endpoint by submitting malformed or unexpected input in request parameters

```http
GET /api/v1/login?user=admin'-- HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Observe the server response and check for detailed error messages returned by the API

```json
{
  "error": "SQL syntax error in users_db at 10.0.0.1",
  "query": "SELECT * FROM users WHERE username = 'admin'--'"
}
```
{% endstep %}

{% step %}
Analyze the response for sensitive information such as Internal database names, Internal IP addresses, SQL queries or Valid usernames or system structure
{% endstep %}

{% step %}
Repeat the request with different malformed inputs to determine whether additional internal system information is disclosed
{% endstep %}

{% step %}
If the API response exposes internal database details, system architecture, or query structures through verbose error messages, the Information Disclosure vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Information Disclosure via Improper Error Handling

{% stepper %}
{% step %}
Navigate to the target web application and identify an endpoint that accepts user-supplied input

```http
GET /product?productId=1 HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Confirm that the application responds normally when a valid numeric value is provided
{% endstep %}

{% step %}
Modify the request by replacing the numeric parameter value with an invalid string input

```http
GET /product?productId=test HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Send the modified request to the server
{% endstep %}

{% step %}
Observe the server response and check whether a **500 Internal Server Error** is returned
{% endstep %}

{% step %}
Scroll through the stack trace output and identify any exposed sensitive information such as Framework name or Internal file paths and ...
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Fallback Execution in Circuit Breaker Topologies

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput microservice architectures, API Gateways, or Service Meshes that govern internal authentication and routing (e.g., Ocelot, Spring Cloud Gateway, Kong)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Resilience and High Availability" architecture. To prevent cascading system failures when a central microservice (like the Identity Provider or Policy Decision Point) experiences latency, developers wrap critical inter-service HTTP calls in Circuit Breakers (e.g., Polly, Resilience4j, Opossum)
{% endstep %}

{% step %}
Investigate the Circuit Breaker's `Fallback` configuration. When the Circuit Breaker trips (transitions to the "Open" state due to excessive timeouts or 500 errors), or when an individual request times out, the framework executes a predefined fallback method instead of throwing a fatal exception
{% endstep %}

{% step %}
Analyze the business logic within the fallback delegate. In complex enterprises, background workers, cron jobs, and asynchronous queue consumers also route through the API Gateway to reach internal services. If the central Auth service goes down, these critical background processes would fail
{% endstep %}

{% step %}
Discover the fatal error-handling optimization: To ensure internal background tasks remain operational during IAM outages, the developer configures the Circuit Breaker fallback to return a static, highly privileged `ServiceAccount` or `SystemAdmin` authorization context
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that Circuit Breakers only trip during genuine, infrastructure-wide network outages. They implicitly trust that if the fallback executes, it is a necessary failsafe for internal systems, failing to distinguish between internal background traffic and external ingress traffic
{% endstep %}

{% step %}
Formulate the Deterministic Error Induction payload. You must manually force the Circuit Breaker to trip or force your specific request to exceed the timeout threshold, invoking the fallback pipeline
{% endstep %}

{% step %}
Identify an execution bottleneck in the target microservice (e.g., the Identity Provider). This could be an extremely long password that triggers bcrypt CPU exhaustion (Regex/Hash DoS), a massive JWT payload that exhausts the JSON parser, or a recursive GraphQL query
{% endstep %}

{% step %}
Submit the computationally expensive payload to the API Gateway's authentication endpoint
{% endstep %}

{% step %}
The Gateway's Circuit Breaker initiates the HTTP call to the Auth service and starts its internal stopwatch
{% endstep %}

{% step %}
The Auth service struggles to process your malicious payload. The Circuit Breaker's execution timer (e.g., 2000ms) expires
{% endstep %}

{% step %}
The Circuit Breaker catches the `TimeoutException`. Instead of returning a `401 Unauthorized` or `503 Service Unavailable`, it seamlessly routes your execution thread into the configured `Fallback` method
{% endstep %}

{% step %}
The Fallback method returns the hardcoded `SystemAdmin` context. The API Gateway assigns this context to your external HTTP request and proxies you to the downstream business microservice. You have successfully achieved unauthenticated, absolute privilege escalation purely by weaponizing the application's own error-handling resilience mechanisms

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.FallbackAsync\s*\(\s*new\s+AuthContext\s*\{[\s\S]{0,120}?Role\s*=\s*"Admin"|\.FallbackAsync\s*\([\s\S]{0,120}?(?:Admin|System|ServiceAccount)|new\s+AuthContext\s*\{[\s\S]{0,80}?(?:Role|IsAdmin))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@Fallback\s*\([\s\S]{0,120}?fallbackMethod\s*=|fallbackMethod\s*=\s*".*(?:Admin|System|Auth)"|new\s+AuthContext\s*\([\s\S]{0,80}?(?:ADMIN|SYSTEM))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$circuitBreaker->setFallback\s*\([\s\S]{0,120}?new\s+AuthContext|setFallback\s*\([\s\S]{0,120}?(?:System|Admin)|new\s+AuthContext\s*\(\s*['"]System['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:breaker\.fallback\s*\([\s\S]{0,150}?role\s*:\s*['"](?:Admin|ServiceAccount|System)['"]|fallback\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,120}?role\s*:|return\s*\{[\s\S]{0,80}?role\s*:\s*['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.FallbackAsync\(.*AuthContext.*Role\s*=\s*"Admin"|FallbackAsync\(.*ServiceAccount
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Fallback\(.*fallbackMethod\s*=.*Admin|new\s+AuthContext\(.*ADMIN
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$circuitBreaker->setFallback\(.*AuthContext\('System'\)|setFallback\(.*Admin
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
breaker\.fallback\(.*role:\s*'ServiceAccount'|fallback\(.*role:\s*'Admin'
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GatewayAuthenticationMiddleware
{
    private readonly AsyncFallbackPolicy<AuthContext> _fallbackPolicy;
    private readonly AsyncTimeoutPolicy _timeoutPolicy;

    public GatewayAuthenticationMiddleware()
    {
        // [1]
        // [2]
        _timeoutPolicy = Policy.TimeoutAsync(TimeSpan.FromSeconds(2));

        // [3]
        // [4]
        // Fails open to ensure internal metrics and cron jobs aren't disrupted by IAM latency
        _fallbackPolicy = Policy<AuthContext>
            .Handle<TimeoutRejectedException>()
            .Or<HttpRequestException>()
            .FallbackAsync(new AuthContext { 
                IsAuthenticated = true, 
                Role = "SystemAdmin", 
                UserId = "SYSTEM_FALLBACK" 
            });
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault();

        // Combines policies: Timeout wraps the HTTP call, Fallback wraps the Timeout
        var authContext = await _fallbackPolicy.WrapAsync(_timeoutPolicy).ExecuteAsync(async () => 
        {
            return await _iamClient.ValidateTokenAsync(token);
        });

        if (authContext.IsAuthenticated)
        {
            context.Items["UserContext"] = authContext;
            await next(context);
        }
        else
        {
            context.Response.StatusCode = 401;
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class GatewayAuthenticationFilter implements GlobalFilter {

    @Autowired
    private IamClient iamClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");

        // [1]
        // [2]
        return iamClient.validateToken(token)
                // [3]
                // [4]
                // Resilience4j annotations or programmatic fallback on Timeout/CircuitBreakerOpen exceptions
                .onErrorResume(TimeoutException.class, e -> Mono.just(getSystemFallbackContext()))
                .flatMap(authContext -> {
                    if (authContext.isAuthenticated()) {
                        exchange.getAttributes().put("UserContext", authContext);
                        return chain.filter(exchange);
                    } else {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                });
    }

    private AuthContext getSystemFallbackContext() {
        AuthContext context = new AuthContext();
        context.setAuthenticated(true);
        context.setRole("SystemAdmin");
        return context;
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
