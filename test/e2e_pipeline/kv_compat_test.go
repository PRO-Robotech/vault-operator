//go:build e2e

package e2e_pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Старый драйвер использует настоящие пакеты v0.0.8; только CM заменён фиксированной записью.
const legacyKVDriver = `package main
import (
 "context"; "flag"; "fmt"; "os"; "strings"
 "k8s.io/apimachinery/pkg/runtime"
 clientgoscheme "k8s.io/client-go/kubernetes/scheme"
 "k8s.io/client-go/tools/clientcmd"
 "sigs.k8s.io/controller-runtime/pkg/client"
 "sigs.k8s.io/controller-runtime/pkg/reconcile"
 api "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
 "github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
 "github.com/PRO-Robotech/vault-operator/internal/controller"
 "github.com/PRO-Robotech/vault-operator/internal/vault"
)
type bucketFixture struct{}
func (bucketFixture) Create(context.Context,cloudmanager.CreateInput)(string,error){return "",fmt.Errorf("unexpected provider create")}
func (bucketFixture) Remove(context.Context,string)error{return fmt.Errorf("unexpected provider remove")}
func (bucketFixture) FindByCustomerBucket(_ context.Context,customer,name string)(*cloudmanager.Bucket,error){
 if customer!="acme" || name!="abcdef-k8s-acme-kvlegacy" {return nil,cloudmanager.ErrBucketNotFound}
 return &cloudmanager.Bucket{Name:name,CustLogin:customer,AccessKey:"fixture-access",SecretKey:"fixture-secret",Fqdn:"fixture.invalid",Cname:"fixture.invalid",Status:cloudmanager.StatusRunning,ManagedBy:cloudmanager.ManagedBySystem},nil
}
func (b bucketFixture) FindByCustomerRequested(c context.Context,customer,name string)(*cloudmanager.Bucket,error){return b.FindByCustomerBucket(c,customer,name)}
func main(){
 kc:=flag.String("apiserver-kubeconfig","","");jf:=flag.String("jwt-file","","");cycles:=flag.Int("cycles",3,"");flag.Parse()
 die:=func(e error){if e!=nil{fmt.Fprintln(os.Stderr,"legacy KV operation failed");os.Exit(1)}}
 cfg,e:=clientcmd.BuildConfigFromFlags("",*kc);die(e);scheme:=runtime.NewScheme();die(clientgoscheme.AddToScheme(scheme));die(api.AddToScheme(scheme))
 c,e:=client.New(cfg,client.Options{Scheme:scheme});die(e);raw,e:=os.ReadFile(*jf);die(e);jwt:=vault.StaticJWTSource(strings.TrimSpace(string(raw)))
 vf:=&controller.DefaultVaultClientFactory{JWTSource:jwt};sf:=&controller.DefaultSecretVaultClientFactory{JWTSource:jwt}
 vc:=&controller.VaultConfigReconciler{Client:c,Scheme:scheme,VaultFactory:vf}
 sc:=&controller.VaultSecretClaimReconciler{Client:c,Scheme:scheme,VaultFactory:sf}
 bc:=&controller.S3BucketClaimReconciler{Client:c,Scheme:scheme,VaultFactory:sf,Buckets:bucketFixture{},DefaultConfigurationID:"s3_v1"}
 ctx:=context.Background();calls:=0
 for i:=0;i<*cycles;i++{
  var configs api.VaultConfigList;die(c.List(ctx,&configs));for _,x:=range configs.Items{_,e:=vc.Reconcile(ctx,reconcile.Request{NamespacedName:client.ObjectKeyFromObject(&x)});die(e)}
  var ss api.VaultSecretClaimList;die(c.List(ctx,&ss));for _,x:=range ss.Items{_,e:=sc.Reconcile(ctx,reconcile.Request{NamespacedName:client.ObjectKeyFromObject(&x)});die(e);calls++}
  var bs api.S3BucketClaimList;die(c.List(ctx,&bs));for _,x:=range bs.Items{_,e:=bc.Reconcile(ctx,reconcile.Request{NamespacedName:client.ObjectKeyFromObject(&x)});die(e);calls++}
 }
 var ss api.VaultSecretClaimList;die(c.List(ctx,&ss));for _,x:=range ss.Items{if x.Status.Phase!=api.PhaseReady || x.Status.ObservedGeneration!=x.Generation{die(fmt.Errorf("legacy secret not Ready"))}}
 var bs api.S3BucketClaimList;die(c.List(ctx,&bs));for _,x:=range bs.Items{if x.Status.Phase!=api.PhaseReady || x.Status.ObservedGeneration!=x.Generation || x.Status.BucketName!="abcdef-k8s-acme-kvlegacy"{die(fmt.Errorf("legacy bucket not Ready"))}}
 if calls==0{die(fmt.Errorf("no calls"))};fmt.Printf("KV_RECONCILE_CALLS=%d\n",calls)
}
`

// fixtureBucket не подменяет Vault: запись KV проходит через настоящий HTTP-клиент.
type fixtureBucket struct{ forbidden int }

func (b *fixtureBucket) Create(context.Context, cloudmanager.CreateInput) (string, error) {
	b.forbidden++
	return "", fmt.Errorf("unexpected provider create")
}
func (b *fixtureBucket) Remove(context.Context, string) error {
	b.forbidden++
	return fmt.Errorf("unexpected provider remove")
}
func (b *fixtureBucket) FindByBucket(_ context.Context, customer, name string) (*cloudmanager.Bucket, error) {
	if customer != "acme" || name != "abcdef-k8s-acme-kvlegacy" {
		return nil, cloudmanager.ErrBucketNotFound
	}
	return &cloudmanager.Bucket{Name: name, CustLogin: customer, AccessKey: "fixture-access", SecretKey: "fixture-secret", Fqdn: "fixture.invalid", Cname: "fixture.invalid", Status: cloudmanager.StatusRunning, ManagedBy: cloudmanager.ManagedBySystem}, nil
}
func (b *fixtureBucket) FindByRequested(ctx context.Context, c, n string, _ bool) ([]*cloudmanager.Bucket, error) {
	v, e := b.FindByBucket(ctx, c, n)
	if e != nil {
		return nil, e
	}
	return []*cloudmanager.Bucket{v}, nil
}
func (b *fixtureBucket) NamesByRequested(context.Context, string, string) ([]string, error) {
	return nil, nil
}

type kvCompatSnapshot struct {
	Hash    string
	Version float64
}

func kvContentsEqual(a, b kvCompatSnapshot) bool {
	return a.Hash != "" && a.Hash == b.Hash && a.Version > 0 && b.Version >= a.Version
}
func (h *harness) kvCompatRead(path string) (kvCompatSnapshot, map[string]any) {
	h.t.Helper()
	body := h.root("GET", "secret/data/"+path, nil)
	if body == nil {
		h.t.Fatal("missing KV destination")
	}
	data := dataOf(body)
	values, ok := data["data"].(map[string]any)
	if !ok || len(values) == 0 {
		h.t.Fatal("empty KV destination")
	}
	md, ok := data["metadata"].(map[string]any)
	if !ok {
		h.t.Fatal("missing KV metadata")
	}
	version, ok := md["version"].(float64)
	if !ok || version < 1 {
		h.t.Fatal("missing KV version")
	}
	canonical, e := json.Marshal(values)
	if e != nil {
		h.t.Fatal("KV canonical encoding failed")
	}
	return kvCompatSnapshot{Hash: fmt.Sprintf("%x", sha256.Sum256(canonical)), Version: version}, values
}
func kvComparisonControls(t *testing.T, s kvCompatSnapshot) {
	t.Helper()
	if !kvContentsEqual(s, s) {
		t.Fatal("same content refused")
	}
	v := s
	v.Version++
	if !kvContentsEqual(s, v) {
		t.Fatal("version-only change refused")
	}
	v.Hash = "different"
	if kvContentsEqual(s, v) {
		t.Fatal("changed content accepted")
	}
	if kvContentsEqual(s, kvCompatSnapshot{}) {
		t.Fatal("missing snapshot accepted")
	}
}
func newKVCompatHarness(t *testing.T) (*harness, string) {
	t.Helper()
	crds, driver := legacyDriverTree(t, "v0.0.8", legacyKVDriver)
	h := newHarness(t, crds)
	h.namespace("acme")
	if e := BootstrapSecretRole(h.ctx, h.vault, mgmtAuthPath, secretRole, []string{operatorSA}, []string{operatorNS}); e != nil {
		t.Fatal("secret bootstrap failed")
	}
	h.vaultConfigObject("kv-compat", secretRole)
	return h, driver
}
func runOldKV(h *harness, driver string) {
	h.t.Helper()
	out := h.runLegacy(driver, 3)
	if strings.TrimSpace(out) != "KV_RECONCILE_CALLS=3" {
		h.t.Fatal("legacy reconciler census mismatch")
	}
}
func assertKVStage(h *harness, stage string, paths []string, baseline map[string]kvCompatSnapshot) {
	h.t.Helper()
	for _, p := range paths {
		s, _ := h.kvCompatRead(p)
		if !kvContentsEqual(baseline[p], s) {
			h.t.Fatalf("KV content mismatch at stage %s", stage)
		}
		h.t.Logf("KV stage=%s hash=%s version=%g delta=%g", stage, s.Hash, s.Version, s.Version-baseline[p].Version)
	}
}
func TestSecretLegacyKVCompatibility(t *testing.T) {
	h, driver := newKVCompatHarness(t)
	if e := SeedKV(h.ctx, h.vault, sharedKVMount, "system/kv-compat", map[string]interface{}{"value": "fixed-source-sentinel"}); e != nil {
		t.Fatal("source seed failed")
	}
	source, _ := h.kvCompatRead("system/kv-compat")
	claim := &api.VaultSecretClaim{ObjectMeta: metav1.ObjectMeta{Name: "kvlegacy", Namespace: "acme"}, Spec: api.VaultSecretClaimSpec{VaultConfigRef: api.VaultConfigRef{Name: "kv-compat"}, ClusterRef: api.SecretClusterRef{Name: "kvlegacy"}, SecretsPrefix: "clusters/kvlegacy", DeletionPolicy: api.DeletionPolicyRetain, SecretList: []api.SecretListItem{
		{Name: "copy", Type: api.SecretTypeCopy, Source: &api.SourceSpec{Path: "system/kv-compat", Key: "value"}, Destination: api.DestinationSpec{Path: "copied", Key: "value"}},
		{Name: "generate", Type: api.SecretTypeGenerate, Generate: &api.GenerateSpec{Length: 20}, Destination: api.DestinationSpec{Path: "generated", Key: "value"}},
	}}}
	if e := h.k8s.Create(h.ctx, claim); e != nil {
		t.Fatal("claim create failed")
	}
	runOldKV(h, driver)
	paths := []string{"clusters/kvlegacy/copied", "clusters/kvlegacy/generated"}
	base := map[string]kvCompatSnapshot{}
	for _, p := range paths {
		s, v := h.kvCompatRead(p)
		base[p] = s
		t.Logf("KV stage=legacy-baseline hash=%s version=%g", s.Hash, s.Version)
		value, ok := v["value"].(string)
		if !ok || (strings.HasSuffix(p, "copied") && value != "fixed-source-sentinel") || (strings.HasSuffix(p, "generated") && len(value) != 20) {
			t.Fatal("legacy KV payload invalid")
		}
		kvComparisonControls(t, s)
	}
	h.installCRDs(filepath.Join("..", "..", "config", "crd", "bases"))
	r := &controller.VaultSecretClaimReconciler{Client: h.k8s, Scheme: h.scheme, VaultFactory: &controller.DefaultSecretVaultClientFactory{JWTSource: vault.StaticJWTSource(h.operatorJWT)}}
	for _, stage := range []string{"current-natural", "current-forced"} {
		if stage == "current-forced" {
			c := &api.VaultSecretClaim{}
			if e := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(claim), c); e != nil {
				t.Fatal("claim read failed")
			}
			old := c.DeepCopy()
			c.Status.ObservedGeneration = 0
			if e := h.k8s.Status().Patch(h.ctx, c, client.MergeFrom(old)); e != nil {
				t.Fatal("force pass failed")
			}
		}
		for i := 0; i < 3; i++ {
			if _, e := r.Reconcile(h.ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(claim)}); e != nil {
				t.Fatal("current secret reconcile failed")
			}
		}
		c := &api.VaultSecretClaim{}
		if e := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(claim), c); e != nil || c.Status.Phase != api.PhaseReady || c.Status.ObservedGeneration != c.Generation {
			t.Fatal("current secret not Ready")
		}
		assertKVStage(h, stage, paths, base)
	}
	runOldKV(h, driver)
	assertKVStage(h, "legacy-rollback", paths, base)
	after, _ := h.kvCompatRead("system/kv-compat")
	if !kvContentsEqual(source, after) {
		t.Fatal("copy source changed")
	}
}
func TestS3LegacyKVCompatibility(t *testing.T) {
	h, driver := newKVCompatHarness(t)
	claim := &api.S3BucketClaim{ObjectMeta: metav1.ObjectMeta{Name: "kvlegacy", Namespace: "acme"}, Spec: api.S3BucketClaimSpec{VaultConfigRef: api.VaultConfigRef{Name: "kv-compat"}, ClusterRef: api.SecretClusterRef{Name: "kvlegacy"}, CustomerLogin: "acme", Region: "ru1", Bucket: api.S3BucketSpec{Name: "abcdef-k8s-acme-kvlegacy", ManagedBy: cloudmanager.ManagedBySystem, ConfigurationID: "s3_v1"}, Vault: api.S3VaultSpec{SecretsPrefix: "clusters/kvlegacy", DestinationPath: "s3"}, DeletionPolicy: api.DeletionPolicyRetain}}
	if e := h.k8s.Create(h.ctx, claim); e != nil {
		t.Fatal("S3 claim create failed")
	}
	// Старый API не знает spec.bucket.name: готовый собственный бакет задан его журналом.
	claim.Status.BucketName = "abcdef-k8s-acme-kvlegacy"
	if e := h.k8s.Status().Update(h.ctx, claim); e != nil {
		t.Fatal("seed existing legacy bucket status failed")
	}
	runOldKV(h, driver)
	path := "clusters/kvlegacy/s3"
	s, v := h.kvCompatRead(path)
	expected := map[string]any{"bucketName": "abcdef-k8s-acme-kvlegacy", "accessKey": "fixture-access", "secretKey": "fixture-secret", "region": "ru1", "endpoint": "s3.ru1.storage.beget.cloud", "cname": "fixture.invalid", "s3ForcePathStyle": "true"}
	if len(v) != len(expected) {
		t.Fatal("legacy S3 KV field census mismatch")
	}
	for k, want := range expected {
		if v[k] != want {
			t.Fatal("legacy S3 KV identity mismatch")
		}
	}
	kvComparisonControls(t, s)
	t.Logf("KV stage=legacy-baseline hash=%s version=%g", s.Hash, s.Version)
	base := map[string]kvCompatSnapshot{path: s}
	h.installCRDs(filepath.Join("..", "..", "config", "crd", "bases"))
	b := &fixtureBucket{}
	r := &controller.S3BucketClaimReconciler{Client: h.k8s, Scheme: h.scheme, VaultFactory: &controller.DefaultSecretVaultClientFactory{JWTSource: vault.StaticJWTSource(h.operatorJWT)}, Buckets: b, DefaultConfigurationID: "s3_v1"}
	for _, stage := range []string{"current-natural", "current-forced"} {
		if stage == "current-forced" {
			c := &api.S3BucketClaim{}
			if e := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(claim), c); e != nil {
				t.Fatal("claim read failed")
			}
			old := c.DeepCopy()
			c.Status.ObservedGeneration = 0
			if e := h.k8s.Status().Patch(h.ctx, c, client.MergeFrom(old)); e != nil {
				t.Fatal("force pass failed")
			}
		}
		for i := 0; i < 3; i++ {
			if _, e := r.Reconcile(h.ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(claim)}); e != nil {
				t.Fatal("current S3 reconcile failed")
			}
		}
		c := &api.S3BucketClaim{}
		if e := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(claim), c); e != nil || c.Status.Phase != api.PhaseReady || c.Status.ObservedGeneration != c.Generation || c.Status.BucketName != "abcdef-k8s-acme-kvlegacy" {
			t.Fatal("current S3 not Ready/own bucket")
		}
		assertKVStage(h, stage, []string{path}, base)
	}
	if b.forbidden != 0 {
		t.Fatal("unexpected provider mutation")
	}
	runOldKV(h, driver)
	assertKVStage(h, "legacy-rollback", []string{path}, base)
}
