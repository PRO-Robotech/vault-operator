//go:build e2e
// +build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/PRO-Robotech/vault-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "vault-operator-system"

// serviceAccountName created for the project
const serviceAccountName = "vault-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "vault-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "vault-operator-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		if keepResources {
			_, _ = fmt.Fprintln(GinkgoWriter, "VAULT_E2E_KEEP set; skipping Manager AfterAll cleanup")
			return
		}
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=vault-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	Context("VaultClaim pipeline (Story 011)", Ordered, func() {
		const (
			claimNS          = "default"
			claimName        = "ec8a00"
			vaultConfigName  = "default"
			mgmtAuthPath     = "kubernetes-mgmt"
			mgmtRole         = "vault-operator-e2e"
			sharedKVMount    = "secret"
			kubeconfigSecret = "ec8a00-infra-kubeconfig"
			adminSAName      = "vault-e2e-admin"
		)

		var (
			portForwardStop   func()
			portForwardCancel context.CancelFunc
			operatorToken     string
		)

		BeforeAll(func() {
			By("deploying Vault dev to the Kind cluster")
			Expect(ApplyVaultManifests()).To(Succeed(), "apply Vault manifests")
			Expect(WaitVaultReady(2 * time.Minute)).To(Succeed(), "wait for Vault Deployment")

			By("starting kubectl port-forward to the Vault Service")
			pfCtx, cancel := context.WithCancel(context.Background())
			portForwardCancel = cancel
			DeferCleanup(func() {
				if !keepResources && portForwardCancel != nil {
					portForwardCancel()
				}
			})
			stop, err := PortForward(pfCtx)
			Expect(err).NotTo(HaveOccurred(), "port-forward to vault")
			portForwardStop = stop

			By("fetching cluster CA + minting operator SA token for Vault TokenReview")
			caPEM, err := FetchClusterRootCA(namespace)
			Expect(err).NotTo(HaveOccurred(), "fetch kube-root-ca.crt")

			By("granting system:auth-delegator to the operator SA (Vault TokenReview)")
			Expect(GrantAuthDelegator(namespace, serviceAccountName, "vault-operator-auth-delegator")).
				To(Succeed(), "grant auth-delegator")

			// IMPORTANT: token_reviewer_jwt must authenticate AS the operator SA
			// to the apiserver — so we mint it with the apiserver's DEFAULT
			// audience (no --audience flag). Minting with --audience=vault would
			// make this token unusable for apiserver auth (apiserver rejects
			// JWTs whose aud doesn't match its own service-account-issuer), and
			// Vault would mask the apiserver 401 as login `permission denied`.
			operatorToken, err = CreateOperatorSAToken(namespace, serviceAccountName, nil)
			Expect(err).NotTo(HaveOccurred(), "mint operator SA token")

			By("bootstrapping Vault: enable auth + write policy + create role")
			Expect(BootstrapVaultInKind(pfCtx,
				"https://kubernetes.default.svc:443",
				caPEM,
				operatorToken,
				mgmtAuthPath,
				mgmtRole,
				namespace,
				serviceAccountName,
			)).To(Succeed(), "bootstrap Vault")

			By("creating a cluster-admin SA + kubeconfig Secret pointing at this cluster")
			adminToken, err := CreateClusterAdminSA(claimNS, adminSAName)
			Expect(err).NotTo(HaveOccurred(), "create cluster-admin SA")
			kubeconfigYAML, err := RenderInClusterKubeconfig(caPEM, adminToken)
			Expect(err).NotTo(HaveOccurred(), "render kubeconfig")
			Expect(ApplyKubeconfigSecret(kubeconfigSecret, claimNS, kubeconfigYAML)).To(Succeed(), "apply kubeconfig Secret")

			By("applying VaultConfig")
			Expect(ApplyVaultConfig(vaultConfigName, mgmtAuthPath, mgmtRole, sharedKVMount)).To(Succeed())
		})

		AfterAll(func() {
			if keepResources {
				_, _ = fmt.Fprintln(GinkgoWriter, "VAULT_E2E_KEEP set; skipping VaultClaim AfterAll cleanup (port-forward stays alive)")
				return
			}
			By("deleting the VaultClaim (idempotent)")
			_ = DeleteVaultClaim(claimName, claimNS)
			By("deleting the kubeconfig Secret + VaultConfig + cluster-admin SA")
			_, _ = utils.Run(exec.Command("kubectl", "delete", "secret", kubeconfigSecret, "-n", claimNS, "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "vaultconfig", vaultConfigName, "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "sa", adminSAName, "-n", claimNS, "--ignore-not-found"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "clusterrolebinding", adminSAName+"-admin", "--ignore-not-found"))
			By("stopping port-forward")
			if portForwardStop != nil {
				portForwardStop()
			}
			By("removing Vault deployment")
			_ = DeleteVaultManifests()
		})

		It("VaultClaim reaches Phase=Ready", func() {
			By("applying VaultClaim")
			Expect(ApplyVaultClaim(claimName, claimNS, vaultConfigName, kubeconfigSecret)).To(Succeed())

			By("waiting until status.phase=Ready")
			Eventually(func(g Gomega) {
				phase, err := GetVaultClaimPhase(claimName, claimNS)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(phase).To(Equal("Ready"), "VaultClaim should reach Ready (got %q)", phase)
			}, 3*time.Minute, 3*time.Second).Should(Succeed())
		})

		It("Vault contains the expected auth mount, policy, and role", func() {
			By("checking auth mount kubernetes-ec8a00/ exists in Vault")
			body, err := vaultGetKindRaw("/v1/sys/auth")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring(`"kubernetes-ec8a00/"`), "auth mount missing in Vault sys/auth")

			By("checking policy ec8a00-vmauth-reader exists")
			body, err = vaultGetKindRaw("/v1/sys/policies/acl?list=true")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("ec8a00-vmauth-reader"), "policy missing in sys/policies/acl")

			By("checking role vmauth-reader exists in the per-cluster auth mount")
			body, err = vaultGetKindRaw("/v1/auth/kubernetes-ec8a00/role?list=true")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring(`"vmauth-reader"`), "role missing in auth/kubernetes-ec8a00/role")
		})

		It("Deleting VaultClaim runs the reverse pipeline", func() {
			By("deleting the VaultClaim and waiting for the object to disappear")
			Expect(DeleteVaultClaim(claimName, claimNS)).To(Succeed())

			By("verifying auth mount is removed from Vault")
			Eventually(func(g Gomega) {
				body, err := vaultGetKindRaw("/v1/sys/auth")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(body)).NotTo(ContainSubstring(`"kubernetes-ec8a00/"`),
					"auth mount kubernetes-ec8a00/ should be gone after delete")
			}, 90*time.Second, 3*time.Second).Should(Succeed())

			By("verifying policy is removed from Vault")
			body, err := vaultGetKindRaw("/v1/sys/policies/acl?list=true")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).NotTo(ContainSubstring("ec8a00-vmauth-reader"),
				"policy ec8a00-vmauth-reader should be gone")
		})
	})
})

// vaultGetKindRaw issues a root-token GET against the locally-forwarded Vault
// and returns the response body. Only used inside this e2e suite.
func vaultGetKindRaw(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", VaultLocalAddr()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", vaultRootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
