# Kubernetes Security Checklist

![4c-cloud](./img/4c-cloud-native.png)

## Table of Contents
  - [Kubernetes Infrastructure](#kubernetes-infrastructure)
  - [Kubernetes Security Features](#kubernetes-security-features)
  - [Kubernetes Authorization - RBAC](#kubernetes-authorization---rbac)
  - [Kubernetes Container Security](#kubernetes-container-security)
  - [Kubernetes Secrets](#kubernetes-secrets)
  - [Kubernetes Networking](#kubernetes-network-security)
  - [Kubernetes Supply Chain Security](#kubernetes-supply-chain-security)
  - [Common attacks](#common-attacks)
  - [Further reading](#further-reading)
  - [Collaborate](#collaborate)

---

## Kubernetes Infrastructure

![infra-k8s](./img/infra-k8s-security.png)

- ✅ limiting access to the Kubernetes API server except from trusted networks.
  - Network access to API Server (Control plane)
  - Network access to Nodes (nodes)
- ✅ Kubernetes access to Cloud Provider API, apply the least privilege.
  - Workload identity in Cloud providers: Employ workload identity to tie RBAC to the cloud provider’s authentication mechanism.
- ✅ Access to etcd
  - etcd Encryption
  - TLS communication
  - is access limited to control plane?
- ✅ host security: OpenSCAP, OVAL. Validate if it's following the CIS benchmark. `Compliance`
- ✅  Updates and patches
  - Update the kubernetes version with the fixed bugs
  - Add-ons installed on the cluster use cert-manager to help keep your site's external certificated up to date.

>> Network boundaries: Control network access
- [Ports and Protocols by kubernetes.io](https://kubernetes.io/docs/reference/ports-and-protocols/)
## Kubernetes Security Features

- ✅ Authorization: RBAC
- ✅ Authentication: SSO
- ✅ Secrets management
- ✅ Pod Security policy
- ✅ Network policy
- ✅ Observability: Auditing API server

## Kubernetes Authorization - RBAC

- ✅ Role-based Access Control - RBAC
  - *Follow the principle of least privilege*
  - Avoid admin-level access in the cluster
      - [AquaSecurity/kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can). Show who has RBAC permissions to perform actions on different resources in Kubernetes.
      - [FairwindsOps/rbac-manager](https://github.com/FairwindsOps/rbac-manager). This is an operator that supports declarative configuration for RBAC with new custom resources.

- [Kubernetes RBAC: Asking for Forgiveness or Getting Permission](https://blog.aquasec.com/kubernetes-rbac)
- [Privilege Escalation from Node/Proxy Rights in Kubernetes RBAC](https://blog.aquasec.com/privilege-escalation-kubernetes-rbac)
- [Kubernetes RBAC: How to Avoid Privilege Escalation via Certificate Signing](https://blog.aquasec.com/kubernetes-rbac-privilige-escalation)
## Kubernetes Container Security
- ✅ [Pod security standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/): Restricted, Baseline and Privileged.
- ✅ Configure a [Security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) for a pod or container.
- ✅ Container runtime with stronger isolation

## Kubernetes Secrets

- ✅ Encrypt all your secrets
    - Mozilla's SOPS
    - Key Management stores in the Cloud Providers
## Kubernetes Network Security

when’s the last time anyone discovered a sophisticated attack from a
packet capture (PCAP) in Kubernetes?

![network-k8s](./img/network-k8s.png)
>> [Image by Security Observability with eBPF](https://isovalent.com/data/isovalent_security_observability.pdf)

- ✅  Network Policy
  - Use nano segmentation
  - Use network policy: manage cluster ingress and egress

## Kubernetes Supply Chain Security
- ✅ Enforce image trust with Image signing
  - Image signing: Container Signing, Verification and Storage in an OCI registry.
  - [Cosign vs Notary by Rewanth](cosign-with-kubernetes-ensure-integrity-of-images-before-deployment)
- ✅ Enabled Kubernetes [Admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) to verify the image integrity.
- ✅ SCA, SBOM

![container-signing](./img/container-signing.png)
## Common Attacks
- Denial of Service (DoS) or a Distributed Denial of Service (DDoS)
  - ✅ Limit the resources (CPU, memory) in the pods
    - [Goldilocks](https://github.com/FairwindsOps/goldilocks) - identify a starting point for resource requests and limits.
  - ✅ Limit the resources (CPU, memory) using Quotes by namespace/cluster.
  - ✅ Set limits about traffic in the ingress policy. You can set limits on the number of concurrent connections, the number of requests per second, minute, or hour; the size of request bodies.
- Fork bomb
- Cryptocurrency mining
- Reverse Shell
- Vulnerabilities and Kubernetes components
- Lateral movement
- Malware
- Fileless exploits
- Remote code execution (RCE) that opens a reverse shell connection to a suspicious domain that the attacker is listening. The workload wasn’t restricted by the
container runtime and has overly permissive Linux capabilities that
enables the attacker to mount in the /etc/kubernetes/manifests directory from the host into the container.
- The attacker then drops a privileged pod manifest in kubelet’s manifest directory. The attacker now has a high-availability, kubelet-managed backdoor into the
cluster that supersedes any IAM (identity and access management) or RBAC policies.

## Policy as a code
OPA allows users to set policies across infrastructure and applications.

- Standard policies.
- Organization-specific policies
- Environment-specific policies

Some controls examples:
• Which registries images can be downloaded from
• Which OS capabilities a container can execute with
• Which namespaces are allowed to run sensitive workloads
• Labels that must be specified for certain resources
• Disallowing deprecated or dangerous resource types
• Enforcing naming schemes or internal standards
### Integrates shift-left Kubernetes Security
Run security validation checks in your CI/CD pipeline. Check the manifest written in in Yaml, Terraform, etc

- [x] IaC and automation reduce human error by creating predictable results
#### Tools
- [FairwindsOps/Polaris](https://github.com/FairwindsOps/Polaris). Validation of best practices in your Kubernetes clusters.
- [AquaSecurity/appshield](https://github.com/aquasecurity/appshield). Security configuration checks for popular cloud native applications and infrastructure.
- [Trivy-operator]
## Kubernetes Reliability Best Practices
- Simplicity vs Complexity
  - Service delivery vs traffic routing. Manually maintained DNS entries, Service delivery is required because your application is scaling in and out, and changes are happening at a fast rate.
  - Configuration management tools: Puppet, Ansible, Terraform
  - Application configuration: ConfigMaps or Secrets
- High-availability (HA) architecture / fault tolerance
- Resource limits and auto-scaling. *set limits on what a pod can consume to increase reliability. This avoids the noisy neighbor problem*
- Liveness and readiness probes. *configure liveness probes and readiness probes to provide your cluster with the ability to self-heal*

### Key Monitoring Alerts
- Kubernetes deployment with no replicas
- Horizontal Pod Autoscaler (HPA) scaling issues
- Host disk usage
- High IO wait times
- Increased network errors
- Increase in pods crashed
- Unhealthy Kubelets
- nginx config reload failures
- Nodes that are not ready
- Large number of pods that are not in a Running state
- External-DNS errors registering records

## Kubernetes CI/CD Artifacts
- argoCD
- gitops
- terraform
- helm
- Istio help handling mutual TLS encryption inside the cluster.
## Further reading:
- [Fairwinds - Kubernetes Best Practices](https://f.hubspotusercontent40.net/hubfs/2184645/Kubernetes-Best-Practices-WhitePaper.pdf)
- [Kubernetes Security Cheat Sheet by Owasp](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [gaps in your public cloud kubernetes security posture](https://itnext.io/how-to-spot-gaps-in-your-public-cloud-kubernetes-security-posture-b9cd375f1b25)
## Collaborate

If you find any typos, errors, outdated resources; or if you have a different point of view. Please open a pull request or contact me.

Pull requests and stars are always welcome 🙌