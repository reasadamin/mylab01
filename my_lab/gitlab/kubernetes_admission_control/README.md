Key Features:

Automated CI/CD pipeline using GitLab CI/CD.
Docker image build and push to GitLab Container Registry.
Vulnerability scanning using Trivy before deployment.
Software Bill of Materials (SBOM) generation using Syft.
Container image signing using Cosign.
Immutable image deployment using image digests instead of tags.
Admission-time policy enforcement using Kyverno.
Runtime security monitoring using Falco.
Automated deployment to a Kubernetes (Minikube) cluster.
Local storage of pipeline outputs on the GitLab Runner.
Automated application verification after deployment.

Security Controls Implemented:

Trivy: Detects HIGH and CRITICAL vulnerabilities in container images.
Syft: Generates SPDX and CycloneDX SBOM files for software supply-chain visibility.
Cosign: Cryptographically signs container image digests to ensure integrity and authenticity.
Kyverno: Verifies image signatures and blocks unsigned images from being deployed.
Falco: Monitors running containers and generates alerts for suspicious runtime activities.

CI/CD Pipeline Workflow:

Build Docker image.
Push image to GitLab Container Registry.
Extract and store image digest locally.
Scan image for vulnerabilities using Trivy.
Generate SBOM files using Syft.
Sign image digest using Cosign.
Deploy signed image to Kubernetes.
Verify deployment and application availability.

Kubernetes Components:

Namespace (pep-test)
Deployment
NodePort Service
Registry Authentication Secret
Kyverno Admission Policies
Falco Runtime Monitoring

Benefits of the Solution:

Improves container supply-chain security.
Prevents deployment of unverified container images.
Provides visibility into software dependencies through SBOMs.
Detects vulnerabilities before deployment.
Enables runtime threat detection.
Supports security for short-lived and dynamic Kubernetes workloads.
Demonstrates practical Zero Trust and DevSecOps principles.

Technologies Used:

GitLab CI/CD
Docker
Kubernetes (Minikube)
Trivy
Syft
Cosign
Kyverno
Falco
GitLab Container Registry
Bash Scripting

Project Objective:

The primary objective of this project is to design and demonstrate a security architecture for ephemeral Kubernetes workloads by integrating vulnerability scanning, software supply-chain visibility, image integrity verification, admission-time policy enforcement, and runtime monitoring into an automated DevSecOps pipeline. The solution aims to improve trust, visibility, and security throughout the container lifecycle while addressing the challenges introduced by dynamic and short-lived Kubernetes environments.