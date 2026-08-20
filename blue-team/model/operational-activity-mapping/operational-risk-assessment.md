# Operational Risk Assessment

## Check List

* [ ] asdsadasdasdasd





## Cheat Sheet

### [Splunk](https://www.splunk.com/)

{% hint style="info" %}
Assess logging coverage across the infrastructure
{% endhint %}

```bash
| metadata type=hosts index=* 
| eval age_hours=round((now()-recentTime)/3600,2) 
| table host, totalCount, age_hours
```

{% hint style="info" %}
Monitor privileged account risk
{% endhint %}

```bash
index=wineventlog EventCode=4624 (Account_Name="Administrator" OR Account_Name="admin") 
| stats count by Account_Name, host, src_ip
```

{% hint style="info" %}
Model the overall operational risk score within a Splunk dashboard
{% endhint %}

```bash
| makeresults 
| eval likelihood=4, impact=5, asset_criticality=5, control_effectiveness=2 
| eval risk_score=round((likelihood * impact * asset_criticality) / control_effectiveness, 2) 
| table asset, risk_score
```

### Linux Operational Risk Assessment

#### [journalctl](https://man7.org/linux/man-pages/man1/journalctl.1.html)

{% hint style="info" %}
Review system warnings and security logs
{% endhint %}

```bash
journalctl -p warning
```

#### [last](https://man7.org/linux/man-pages/man1/last.1.html)

{% hint style="info" %}
Audit recent user login sessions
{% endhint %}

```bash
last
```

{% hint style="info" %}
Check local accounts & sudoers
{% endhint %}

```bash
cat /etc/passwd
sudo -l
grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/
```

### Windows Operational Risk Assessment

#### [auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)

{% hint style="info" %}
Verify active security audit policies
{% endhint %}

```cmd
auditpol /get /category:*
```

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Retrieve recent security events for risk analysis
{% endhint %}

```powershell
Get-WinEvent -LogName Security -MaxEvents 20
```

{% hint style="info" %}
Check Active Directory members
{% endhint %}

```bash
Get-ADGroupMember $GROUP_NAME
```

### Source Code & Git (Asset & Dependency Discovery)

#### [git](https://git-scm.com/)

{% hint style="info" %}
Map remote repositories and branch structures
{% endhint %}

```bash
git remote -v && git branch -a
```

{% hint style="info" %}
Audit recent commit history and metadata
{% endhint %}

```bash
git log --oneline --decorate -n 20
```

{% hint style="info" %}
Monitor changes in critical infrastructure files (Dockerfile, Manifests, Configs)
{% endhint %}

```bash
git diff --name-only HEAD~1 HEAD | grep -E "Dockerfile|requirements.txt|package.json|pom.xml|go.mod|.env|yaml|yml|json"
```

#### [find](https://man7.org/linux/man-pages/man1/find.1.html)

{% hint style="info" %}
Identify sensitive configuration and environment files
{% endhint %}

```bash
find . -type f \( -name "*.env" -o -name "config.*" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" \)
```

{% hint style="info" %}
Locate software dependency manifests
{% endhint %}

```bash
find . -type f \( -name "package.json" -o -name "requirements.txt" -o -name "pom.xml" -o -name "go.mod" -o -name "Gemfile" -o -name "composer.json" \)
```

### Software Composition & Security Scanning (SAST/SCA)

#### [Semgrep](https://semgrep.dev/)

{% hint style="info" %}
Static Analysis Security Testing (SAST) for logic flaws
{% endhint %}

```bash
semgrep scan --config auto .
```

#### [gitleaks](https://gitleaks.org/)

{% hint style="info" %}
Scan for hardcoded secrets and credentials in the filesystem
{% endhint %}

```bash
gitleaks detect --source . --verbose
```

#### [trufflehog](https://trufflesecurity.com/trufflehog)

{% hint style="info" %}
Identify secrets in git history using entropy analysis
{% endhint %}

```bash
trufflehog filesystem .
```

#### [trivy](https://trivy.dev/)

{% hint style="info" %}
Vulnerability scanning for container images
{% endhint %}

```bash
trivy image nginx:latest
```

{% hint style="info" %}
Software Composition Analysis (SCA) for project directories
{% endhint %}

```bash
trivy fs .
```

{% hint style="info" %}
Scan Infrastructure as Code (IaC) and Kubernetes manifests
{% endhint %}

```bash
trivy config .
```

#### [npm](https://www.npmjs.com/)

{% hint style="info" %}
Audit Node.js dependencies for known vulnerabilities
{% endhint %}

```bash
npm audit
```

#### [Python](https://www.python.org/)

{% hint style="info" %}
Python dependency vulnerability auditing
{% endhint %}

```bash
pip-audit
# OR
safety check
```

#### [mvn](https://maven.apache.org/)

{% hint style="info" %}
Analyze Java/Maven dependency trees and vulnerabilities
{% endhint %}

```bash
mvn dependency:tree
mvn org.owasp:dependency-check-maven:check
```

### Kubernetes

#### [kubectl](https://kubernetes.io/docs/concepts/overview/kubectl/)

{% hint style="info" %}
Inventory nodes and cluster infrastructure
{% endhint %}

```bash
kubectl get nodes -o wide
```

{% hint style="info" %}
Audit running workloads and services across all namespaces
{% endhint %}

```bash
kubectl get pods -A && kubectl get svc -A
```

{% hint style="info" %}
Map cluster-wide identity permissions (RBAC)
{% endhint %}

```bash
kubectl get clusterrolebindings
```

{% hint style="info" %}
Verify current user permissions against the API server
{% endhint %}

```bash
kubectl auth can-i --list
```
