package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseCacheCoveragePlan(t *testing.T, name string) (DFD, []string) {
	t.Helper()
	plan, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "fluong/fray", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func cacheElementByAddress(doc DFD, addr string) (Element, bool) {
	for _, el := range doc.Elements {
		if len(el.Evidence.Addresses) > 0 && el.Evidence.Addresses[0] == addr {
			return el, true
		}
	}
	return Element{}, false
}

func TestCoverageCacheFixturesABC(t *testing.T) {
	doc, _ := parseCacheCoveragePlan(t, "coverage-cache-plan.json")

	t.Run("A_cache_redis_secure", func(t *testing.T) {
		el, ok := cacheElementByAddress(doc, "aws_elasticache_replication_group.cache_redis_secure")
		if !ok {
			t.Fatal("missing element")
		}
		if el.Kind != "cache" || el.ProviderSubtype != "redis" {
			t.Fatalf("kind/subtype=%q/%q", el.Kind, el.ProviderSubtype)
		}
		if el.Attributes["network_restricted"] != true || el.Attributes["tls_enforced"] != true || el.Attributes["encrypted_at_rest"] != true {
			t.Fatalf("attrs=%v", el.Attributes)
		}
	})
	t.Run("B_cache_redis_open", func(t *testing.T) {
		el, ok := cacheElementByAddress(doc, "aws_elasticache_replication_group.cache_redis_open")
		if !ok {
			t.Fatal("missing element")
		}
		if el.Attributes["network_restricted"] != false || el.Attributes["tls_enforced"] != false || el.Attributes["encrypted_at_rest"] != false {
			t.Fatalf("attrs=%v", el.Attributes)
		}
	})
	t.Run("C_cache_memcached", func(t *testing.T) {
		el, ok := cacheElementByAddress(doc, "aws_elasticache_cluster.cache_memcached")
		if !ok {
			t.Fatal("missing element")
		}
		if el.ProviderSubtype != "memcached" {
			t.Fatalf("subtype=%q", el.ProviderSubtype)
		}
		if el.Attributes["network_restricted"] != true || el.Attributes["tls_enforced"] != true {
			t.Fatalf("attrs=%v", el.Attributes)
		}
		if _, has := el.Attributes["encrypted_at_rest"]; has {
			t.Fatalf("memcached must omit encrypted_at_rest; attrs=%v", el.Attributes)
		}
	})
}

func TestCoverageCacheMemberClusterOmitted(t *testing.T) {
	plan := []byte(`{"format_version":"1.2","terraform_version":"1.16.6","resource_changes":[
{"address":"aws_elasticache_replication_group.primary","mode":"managed","type":"aws_elasticache_replication_group","name":"primary","change":{"actions":["create"],"after":{"replication_group_id":"primary","engine":"redis","transit_encryption_enabled":true}}},
{"address":"aws_elasticache_cluster.primary_member","mode":"managed","type":"aws_elasticache_cluster","name":"primary_member","change":{"actions":["create"],"after":{"cluster_id":"primary-001","engine":"redis","replication_group_id":"primary"}}}
],"configuration":{"root_module":{"resources":[
{"address":"aws_elasticache_cluster.primary_member","expressions":{"replication_group_id":{"references":["aws_elasticache_replication_group.primary.id"]}}}
]}}}`)
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/cache", Commit: "c000001", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var members, groups int
	for _, el := range doc.Elements {
		if el.Kind != "cache" {
			continue
		}
		if len(el.Evidence.Addresses) == 0 {
			continue
		}
		switch el.Evidence.Addresses[0] {
		case "aws_elasticache_cluster.primary_member":
			members++
		case "aws_elasticache_replication_group.primary":
			groups++
		}
	}
	if members != 0 || groups != 1 {
		t.Fatalf("want replication group only; members=%d groups=%d elements=%d", members, groups, len(doc.Elements))
	}
}

func TestCoverageCacheServerlessWarning(t *testing.T) {
	_, warnings := parseCacheCoveragePlan(t, "coverage-cache-serverless-plan.json")
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "aws_elasticache_serverless_cache.example") && strings.Contains(w, "no mapping") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want serverless no-mapping warning; got %v", warnings)
	}
}
