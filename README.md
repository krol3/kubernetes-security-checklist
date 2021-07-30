# Kubernetes Security Checklist

## Common threads
- [x] Denial of Service (DoS) or a Distributed Denial of Service (DDoS)
  - [x] Limit the resources (CPU, memory) in the pods
    - [Goldilocks](https://github.com/FairwindsOps/goldilocks) - identify a starting point for resource requests and limits.
  - [x] Limit the resources (CPU, memory) using Quotes by namespace/cluster.
  - [x] Set limits about traffic in the ingress policy. You can set limits on the number of concurrent connections, the number of requests per second, minute, or hour; the size of request bodies.
- [x] Crypto miners
- [x] Reverse Shell
- [x] Dos

## Security Checklist
- [x] Updates and patches
  - [x] Update the kubernetes version with with the fixed bugs
  - [x] Add-ons installed on the cluster use cert-manager to help keep your site's external certificated up to date.
  - [x] Istio help handling mutual TLS encryption inside the cluster.
  - [x] IaC and automation reduce human error by creating predictable results
- [x] Role-based Access Control - RBAC
  - *Follow the principle of least privilege*
  - [x] Avoid admin-level access in the cluster
      - [AquaSecurity/kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can). Show who has RBAC permissions to perform actions on different resources in Kubernetes.
      - [FairwindsOps/rbac-manager](https://github.com/FairwindsOps/rbac-manager). This is an operator that supports declarative configuration for RBAC with new custom resources.
- [x] Network Policy
  - [x] Use nano segmentation
  - [x] Use network policy: manage cluster ingress and egress
- [x] Workload identity in Cloud providers: Employ workload identity to tie RBAC to the cloud provider’s
authentication mechanism
- [x] Secrets
  - [x] Encrypt all your secrets
    - Mozilla's SOPS
    - Key Management stores in the Cloud Providers

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
Run security validation checks in your CI/CD pipeline. Check the manifest writte in in Yaml, Terraform, etc

#### Tools
- [FairwindsOps/Polaris](https://github.com/FairwindsOps/Polaris). Validation of best practices in your Kubernetes clusters.
- [AquaSecurity/appshield](https://github.com/aquasecurity/appshield). Security configuration checks for popular cloud native applications and infrastructure.
- [starboard]
## Kubernetes Reliability Best Practices
- Simplicity vs Complexity
  - Service delivery vs traffic routing. Manually maintained DNS entries, Service delivery is required because your application is scaling in and out, and changes are happening at a fast rate.
  - Configuration management tools: Puppet, Ansible, Terraform
  - Application configuration: ConfigMaps or Secrets
- High-availability (HA) architecture / fault tolerance
- Resource limits and autoscaling. *set limits on what a pod can consume to increase reliability. This avoids the noisy neighbor problem*
- Liveness and readiness probes. *configure liveness probes and readiness probes to provide your cluster with the ability to self-heal*

### Key Monitoring Alerts
• Kubernetes deployment with no replicas
• Horizontal Pod Autoscaler (HPA) scaling issues
• Host disk usage
• High IO wait times
• Increased network errors
• Increase in pods crashed
• Unhealthy Kubelets
• nginx config reload failures
• Nodes that are not ready
• Large number of pods that are not in a Running state
• External-DNS errors registering records
## Resources
- [Fairwinds - Kubernetes Best Practices](https://f.hubspotusercontent40.net/hubfs/2184645/Kubernetes-Best-Practices-WhitePaper.pdf)