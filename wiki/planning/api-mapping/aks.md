# aks API Mapping

## Slice Goal

Surface operator-first AKS cluster posture with a narrow Azure-native depth pass.

This version answers:
"Which AKS clusters expose the most interesting control-plane endpoint, identity context, auth
posture, and Azure-native federation or addon cues for operator follow-up?"

## Initial Scope

- AKS managed cluster enumeration
- Public versus private control-plane endpoint visibility
- Cluster identity attachment context, including managed-identity-backed and
  service-principal-backed clusters when visible
- Managed AAD, Azure RBAC, and local-account posture
- Basic network-shape signals such as plugin, policy, and outbound mode
- OIDC issuer and workload identity posture
- Enabled addon names and simple web-app-routing ingress-profile cues

## Explicit Non-Goals For V1

- Kubernetes workload, namespace, pod, or service enumeration
- Kubeconfig retrieval, cluster credential collection, or node access paths
- Node-pool deep analysis beyond simple pool counts
- Ingress, internal load balancer, or private DNS path modeling

## Primary APIs

- `azure.mgmt.containerservice.ContainerServiceClient.managed_clusters.list`

## Correlation / Joins

- Normalize cluster-level control-plane exposure, identity, auth, and network metadata into a
  single operator-first row
- Add a small amount of Azure-native federation and addon posture without crossing into cluster
  access or Kubernetes-object collection
- Keep the slice focused on management-plane cluster posture without implying in-cluster visibility

## Blind Spots

- V1 does not prove Kubernetes API reachability from the current network position
- Cluster auth posture does not show actual Entra group assignments or in-cluster RBAC objects
- Network-shape signals do not prove ingress paths to workloads running behind the cluster
- OIDC, workload identity, and addon cues are management-plane posture hints, not proof of usable
  cluster access
