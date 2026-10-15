package client

import (
	"strings"
	"testing"
)

// B-56a: plain aws_lb → aws_lb_listener/rule → aws_lb_target_group ←
// aws_ecs_service.load_balancer fronts container_service (same outcome as
// terraform-aws-modules/alb via servicesFrontedByModule).

type plainALBOpts struct {
	internal       bool
	tgProtocol     string // HTTP | HTTPS
	attachECS      bool
	cognitoThenFwd bool // default_action: authenticate-cognito then forward
	ruleForward    bool // aws_lb_listener_rule forward (no default forward)
	tgViaVar       bool // target_group_arn references var.x (unresolvable)
}

func plainALBECSPlan(t *testing.T, o plainALBOpts) string {
	t.Helper()
	if o.tgProtocol == "" {
		o.tgProtocol = "HTTP"
	}
	listenerPort := float64(80)
	listenerProto := "HTTP"
	if o.tgProtocol == "HTTPS" {
		listenerPort = 443
		listenerProto = "HTTPS"
	}

	var defaultActions []any
	var defaultActionExpr []any
	switch {
	case o.ruleForward:
		// Redirect-only default so the edge still exists; app forward is on the rule.
		defaultActions = []any{map[string]any{
			"type": "redirect",
			"redirect": []any{map[string]any{
				"port": "443", "protocol": "HTTPS", "status_code": "HTTP_301",
			}},
		}}
		defaultActionExpr = []any{map[string]any{
			"type": map[string]any{"constant_value": "redirect"},
		}}
	case o.cognitoThenFwd:
		defaultActions = []any{
			map[string]any{
				"type": "authenticate-cognito", "order": float64(1),
				"authenticate_cognito": []any{map[string]any{
					"user_pool_arn": "arn:aws:cognito-idp:us-east-1:1:userpool/x",
				}},
			},
			map[string]any{
				"type": "forward", "order": float64(2),
				"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
			},
		}
		fwdExpr := map[string]any{
			"type": map[string]any{"constant_value": "forward"},
			"order": map[string]any{"constant_value": float64(2)},
		}
		if o.tgViaVar {
			fwdExpr["target_group_arn"] = map[string]any{"references": []any{"var.app_tg_arn", "var.app_tg_arn"}}
		} else {
			fwdExpr["target_group_arn"] = map[string]any{"references": []any{
				"aws_lb_target_group.app.arn", "aws_lb_target_group.app",
			}}
		}
		defaultActionExpr = []any{
			map[string]any{
				"type":  map[string]any{"constant_value": "authenticate-cognito"},
				"order": map[string]any{"constant_value": float64(1)},
				"authenticate_cognito": []any{map[string]any{
					"user_pool_arn": map[string]any{"constant_value": "arn:aws:cognito-idp:us-east-1:1:userpool/x"},
				}},
			},
			fwdExpr,
		}
	default:
		defaultActions = []any{map[string]any{
			"type":             "forward",
			"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
		}}
		fwdExpr := map[string]any{
			"type": map[string]any{"constant_value": "forward"},
		}
		if o.tgViaVar {
			fwdExpr["target_group_arn"] = map[string]any{"references": []any{"var.app_tg_arn"}}
		} else {
			fwdExpr["target_group_arn"] = map[string]any{"references": []any{
				"aws_lb_target_group.app.arn", "aws_lb_target_group.app",
			}}
		}
		defaultActionExpr = []any{fwdExpr}
	}

	resources := []map[string]any{
		{
			"address": "aws_lb.app", "mode": "managed", "type": "aws_lb", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"name": "app", "internal": o.internal,
			}},
		},
		{
			"address": "aws_security_group.alb", "mode": "managed", "type": "aws_security_group", "name": "alb",
			"change": map[string]any{"after": map[string]any{
				"ingress": []any{map[string]any{
					"from_port": listenerPort, "to_port": listenerPort, "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}},
			}},
		},
		{
			"address": "aws_lb_target_group.app", "mode": "managed", "type": "aws_lb_target_group", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"name": "app", "port": listenerPort, "protocol": o.tgProtocol, "target_type": "ip",
			}},
		},
		{
			"address": "aws_lb_listener.front", "mode": "managed", "type": "aws_lb_listener", "name": "front",
			"change": map[string]any{"after": map[string]any{
				"port": listenerPort, "protocol": listenerProto,
				"default_action": defaultActions,
			}},
		},
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"family":                "app",
				"container_definitions": `[{"name":"app","image":"app:1","portMappings":[{"containerPort":8080}]}]`,
			}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_lb.app", "type": "aws_lb", "name": "app",
			"expressions": map[string]any{
				"security_groups": map[string]any{"references": []any{
					"aws_security_group.alb.id", "aws_security_group.alb",
				}},
			},
		},
		{"address": "aws_security_group.alb", "type": "aws_security_group", "name": "alb", "expressions": map[string]any{}},
		{"address": "aws_lb_target_group.app", "type": "aws_lb_target_group", "name": "app", "expressions": map[string]any{}},
		{
			"address": "aws_lb_listener.front", "type": "aws_lb_listener", "name": "front",
			"expressions": map[string]any{
				"load_balancer_arn": map[string]any{"references": []any{"aws_lb.app.arn", "aws_lb.app"}},
				"default_action":    defaultActionExpr,
			},
		},
		{
			"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app",
			"expressions": map[string]any{},
		},
	}

	svcExpr := map[string]any{
		"task_definition": map[string]any{"references": []any{
			"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app",
		}},
	}
	if o.attachECS {
		svcExpr["load_balancer"] = []any{map[string]any{
			"target_group_arn": map[string]any{"references": []any{
				"aws_lb_target_group.app.arn", "aws_lb_target_group.app",
			}},
			"container_name": map[string]any{"constant_value": "app"},
			"container_port": map[string]any{"constant_value": float64(8080)},
		}}
		resources[4]["change"] = map[string]any{"after": map[string]any{
			"name": "app",
			"load_balancer": []any{map[string]any{
				"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
				"container_name":   "app",
				"container_port":   float64(8080),
			}},
		}}
	}
	cfg = append(cfg, map[string]any{
		"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app",
		"expressions": svcExpr,
	})

	if o.ruleForward {
		ruleActions := []any{map[string]any{
			"type": "forward",
			"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
		}}
		ruleExprActions := []any{map[string]any{
			"type": map[string]any{"constant_value": "forward"},
			"target_group_arn": map[string]any{"references": []any{
				"aws_lb_target_group.app.arn", "aws_lb_target_group.app",
			}},
		}}
		resources = append(resources, map[string]any{
			"address": "aws_lb_listener_rule.app", "mode": "managed", "type": "aws_lb_listener_rule", "name": "app",
			"change": map[string]any{"after": map[string]any{"action": ruleActions}},
		})
		cfg = append(cfg, map[string]any{
			"address": "aws_lb_listener_rule.app", "type": "aws_lb_listener_rule", "name": "app",
			"expressions": map[string]any{
				"listener_arn": map[string]any{"references": []any{
					"aws_lb_listener.front.arn", "aws_lb_listener.front",
				}},
				"action": ruleExprActions,
			},
		})
	}

	return marshalPlan(t, resources, cfg)
}

func TestPlainALBFrontsECS(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/plain-alb", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	flowLBToECS := func(doc DFD) *Flow {
		lb := findKind(doc, "load_balancer")
		svc := findKind(doc, "container_service")
		if lb.Kind != "load_balancer" || svc.Kind != "container_service" {
			return nil
		}
		for i := range doc.Flows {
			f := &doc.Flows[i]
			if f.From == lb.ID && f.To == svc.ID {
				return f
			}
		}
		return nil
	}
	edgeScope := func(doc DFD) string {
		pub := findKind(doc, "public_client")
		lb := findKind(doc, "load_balancer")
		if pub.Kind != "public_client" || lb.Kind != "load_balancer" {
			return ""
		}
		for i := range doc.Flows {
			f := &doc.Flows[i]
			if f.From == pub.ID && f.To == lb.ID {
				return f.AuthzScope
			}
		}
		return ""
	}

	t.Run("http_forward_plaintext", func(t *testing.T) {
		doc, warnings, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{attachECS: true, tgProtocol: "HTTP"})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f := flowLBToECS(doc)
		if f == nil {
			t.Fatal("want LB→ECS flow")
		}
		if f.Transport != "plaintext" {
			t.Fatalf("transport=%q want plaintext", f.Transport)
		}
		for _, w := range warnings {
			if strings.Contains(w, "unresolvable target group") {
				t.Fatalf("unexpected warning %q", w)
			}
		}
	})

	t.Run("https_forward_tls", func(t *testing.T) {
		doc, _, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{attachECS: true, tgProtocol: "HTTPS"})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f := flowLBToECS(doc)
		if f == nil {
			t.Fatal("want LB→ECS flow")
		}
		if f.Transport != "tls" {
			t.Fatalf("transport=%q want tls", f.Transport)
		}
	})

	t.Run("cognito_then_forward_still_fronts", func(t *testing.T) {
		doc, _, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{
			attachECS: true, tgProtocol: "HTTPS", cognitoThenFwd: true,
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if flowLBToECS(doc) == nil {
			t.Fatal("want LB→ECS flow behind cognito+forward")
		}
		if got := edgeScope(doc); got != "authenticated" {
			t.Fatalf("public_client→LB authz_scope=%q want authenticated", got)
		}
	})

	t.Run("listener_rule_forward", func(t *testing.T) {
		doc, _, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{
			attachECS: true, tgProtocol: "HTTP", ruleForward: true,
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if flowLBToECS(doc) == nil {
			t.Fatal("want LB→ECS flow from listener_rule forward")
		}
	})

	t.Run("ecs_not_attached", func(t *testing.T) {
		doc, _, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{attachECS: false})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if flowLBToECS(doc) != nil {
			t.Fatal("ECS without load_balancer must not be fronted")
		}
		if findKind(doc, "load_balancer").Kind != "load_balancer" {
			t.Fatal("want load_balancer element")
		}
		if findKind(doc, "public_client").Kind != "public_client" {
			t.Fatal("want public_client on internet-facing LB")
		}
	})

	t.Run("internal_lb_no_public_path", func(t *testing.T) {
		doc, _, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{
			internal: true, attachECS: true,
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		lb := findKind(doc, "load_balancer")
		if lb.Kind != "load_balancer" {
			t.Fatal("want load_balancer element")
		}
		if lb.Attributes["public"] == true {
			t.Fatalf("internal LB public=%v want not true", lb.Attributes["public"])
		}
		if findKind(doc, "public_client").Kind == "public_client" {
			t.Fatal("internal LB must not invent public_client")
		}
		if flowLBToECS(doc) != nil {
			t.Fatal("internal LB must not emit LB→ECS public fronting flow")
		}
	})

	t.Run("tg_via_var_warn_no_flow", func(t *testing.T) {
		doc, warnings, err := Parse([]byte(plainALBECSPlan(t, plainALBOpts{
			attachECS: true, tgViaVar: true,
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if flowLBToECS(doc) != nil {
			t.Fatal("var target group must not invent LB→ECS flow")
		}
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "unresolvable target group behind aws_lb.app") {
				found = true
			}
		}
		if !found {
			t.Fatalf("want unresolvable target group warning, got %v", warnings)
		}
	})
}

func TestPlainALBTwoServicesPerTGTransport(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/plain-alb-multi", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	// One public ALB, HTTPS listener; two rules → api (HTTPS TG) and admin (HTTP TG);
	// two ECS services attached respectively.
	resources := []map[string]any{
		{
			"address": "aws_lb.app", "mode": "managed", "type": "aws_lb", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app", "internal": false}},
		},
		{
			"address": "aws_security_group.alb", "mode": "managed", "type": "aws_security_group", "name": "alb",
			"change": map[string]any{"after": map[string]any{
				"ingress": []any{map[string]any{
					"from_port": float64(443), "to_port": float64(443), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}},
			}},
		},
		{
			"address": "aws_lb_target_group.api", "mode": "managed", "type": "aws_lb_target_group", "name": "api",
			"change": map[string]any{"after": map[string]any{
				"name": "api", "port": float64(443), "protocol": "HTTPS", "target_type": "ip",
			}},
		},
		{
			"address": "aws_lb_target_group.admin", "mode": "managed", "type": "aws_lb_target_group", "name": "admin",
			"change": map[string]any{"after": map[string]any{
				"name": "admin", "port": float64(80), "protocol": "HTTP", "target_type": "ip",
			}},
		},
		{
			"address": "aws_lb_listener.https", "mode": "managed", "type": "aws_lb_listener", "name": "https",
			"change": map[string]any{"after": map[string]any{
				"port": float64(443), "protocol": "HTTPS",
				"default_action": []any{map[string]any{
					"type": "fixed-response",
					"fixed_response": []any{map[string]any{"content_type": "text/plain", "status_code": "404"}},
				}},
			}},
		},
		{
			"address": "aws_lb_listener_rule.api", "mode": "managed", "type": "aws_lb_listener_rule", "name": "api",
			"change": map[string]any{"after": map[string]any{
				"action": []any{map[string]any{
					"type": "forward", "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/api/x",
				}},
			}},
		},
		{
			"address": "aws_lb_listener_rule.admin", "mode": "managed", "type": "aws_lb_listener_rule", "name": "admin",
			"change": map[string]any{"after": map[string]any{
				"action": []any{map[string]any{
					"type": "forward", "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/admin/x",
				}},
			}},
		},
		{
			"address": "aws_ecs_service.api", "mode": "managed", "type": "aws_ecs_service", "name": "api",
			"change": map[string]any{"after": map[string]any{
				"name": "api",
				"load_balancer": []any{map[string]any{
					"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/api/x",
					"container_name":   "api", "container_port": float64(8080),
				}},
			}},
		},
		{
			"address": "aws_ecs_service.admin", "mode": "managed", "type": "aws_ecs_service", "name": "admin",
			"change": map[string]any{"after": map[string]any{
				"name": "admin",
				"load_balancer": []any{map[string]any{
					"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/admin/x",
					"container_name":   "admin", "container_port": float64(8080),
				}},
			}},
		},
		{
			"address": "aws_ecs_task_definition.api", "mode": "managed", "type": "aws_ecs_task_definition", "name": "api",
			"change": map[string]any{"after": map[string]any{
				"family": "api", "container_definitions": `[{"name":"api","image":"api:1"}]`,
			}},
		},
		{
			"address": "aws_ecs_task_definition.admin", "mode": "managed", "type": "aws_ecs_task_definition", "name": "admin",
			"change": map[string]any{"after": map[string]any{
				"family": "admin", "container_definitions": `[{"name":"admin","image":"admin:1"}]`,
			}},
		},
	}
	cfgRes := []map[string]any{
		{
			"address": "aws_lb.app", "type": "aws_lb", "name": "app",
			"expressions": map[string]any{
				"security_groups": map[string]any{"references": []any{"aws_security_group.alb.id", "aws_security_group.alb"}},
			},
		},
		{"address": "aws_security_group.alb", "type": "aws_security_group", "name": "alb", "expressions": map[string]any{}},
		{"address": "aws_lb_target_group.api", "type": "aws_lb_target_group", "name": "api", "expressions": map[string]any{}},
		{"address": "aws_lb_target_group.admin", "type": "aws_lb_target_group", "name": "admin", "expressions": map[string]any{}},
		{
			"address": "aws_lb_listener.https", "type": "aws_lb_listener", "name": "https",
			"expressions": map[string]any{
				"load_balancer_arn": map[string]any{"references": []any{"aws_lb.app.arn", "aws_lb.app"}},
				"default_action": []any{map[string]any{
					"type": map[string]any{"constant_value": "fixed-response"},
				}},
			},
		},
		{
			"address": "aws_lb_listener_rule.api", "type": "aws_lb_listener_rule", "name": "api",
			"expressions": map[string]any{
				"listener_arn": map[string]any{"references": []any{"aws_lb_listener.https.arn", "aws_lb_listener.https"}},
				"action": []any{map[string]any{
					"type": map[string]any{"constant_value": "forward"},
					"target_group_arn": map[string]any{"references": []any{
						"aws_lb_target_group.api.arn", "aws_lb_target_group.api",
					}},
				}},
			},
		},
		{
			"address": "aws_lb_listener_rule.admin", "type": "aws_lb_listener_rule", "name": "admin",
			"expressions": map[string]any{
				"listener_arn": map[string]any{"references": []any{"aws_lb_listener.https.arn", "aws_lb_listener.https"}},
				"action": []any{map[string]any{
					"type": map[string]any{"constant_value": "forward"},
					"target_group_arn": map[string]any{"references": []any{
						"aws_lb_target_group.admin.arn", "aws_lb_target_group.admin",
					}},
				}},
			},
		},
		{
			"address": "aws_ecs_service.api", "type": "aws_ecs_service", "name": "api",
			"expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.api.arn", "aws_ecs_task_definition.api"}},
				"load_balancer": []any{map[string]any{
					"target_group_arn": map[string]any{"references": []any{"aws_lb_target_group.api.arn", "aws_lb_target_group.api"}},
					"container_name":   map[string]any{"constant_value": "api"},
					"container_port":   map[string]any{"constant_value": float64(8080)},
				}},
			},
		},
		{
			"address": "aws_ecs_service.admin", "type": "aws_ecs_service", "name": "admin",
			"expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.admin.arn", "aws_ecs_task_definition.admin"}},
				"load_balancer": []any{map[string]any{
					"target_group_arn": map[string]any{"references": []any{"aws_lb_target_group.admin.arn", "aws_lb_target_group.admin"}},
					"container_name":   map[string]any{"constant_value": "admin"},
					"container_port":   map[string]any{"constant_value": float64(8080)},
				}},
			},
		},
		{"address": "aws_ecs_task_definition.api", "type": "aws_ecs_task_definition", "name": "api", "expressions": map[string]any{}},
		{"address": "aws_ecs_task_definition.admin", "type": "aws_ecs_task_definition", "name": "admin", "expressions": map[string]any{}},
	}

	doc, warnings, err := Parse([]byte(marshalPlan(t, resources, cfgRes)), cfg, "", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous service") {
			t.Fatalf("plain multi-service must not warn ambiguous: %v", warnings)
		}
	}
	lb := findKind(doc, "load_balancer")
	if lb.Kind != "load_balancer" {
		t.Fatal("want load_balancer")
	}
	byAddr := map[string]*Element{}
	for i := range doc.Elements {
		el := &doc.Elements[i]
		if len(el.Evidence.Addresses) == 1 {
			byAddr[el.Evidence.Addresses[0]] = el
		}
	}
	api, admin := byAddr["aws_ecs_service.api"], byAddr["aws_ecs_service.admin"]
	if api == nil || admin == nil {
		t.Fatalf("missing services: api=%v admin=%v", api != nil, admin != nil)
	}
	got := map[string]string{}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.From != lb.ID {
			continue
		}
		switch f.To {
		case api.ID:
			got["api"] = f.Transport
		case admin.ID:
			got["admin"] = f.Transport
		}
	}
	if got["api"] != "tls" {
		t.Fatalf("api transport=%q want tls (got map %v)", got["api"], got)
	}
	if got["admin"] != "plaintext" {
		t.Fatalf("admin transport=%q want plaintext (got map %v)", got["admin"], got)
	}
}

func TestPlainALBModuleScopeNoCrossFront(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/plain-alb-scope", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	// Root LB + root TG; module.x ECS references module-relative aws_lb_target_group.app
	// (a different resource in module.x). Root LB must not front module.x's service via
	// name-only matching against the root TG.
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"aws_lb.app","mode":"managed","type":"aws_lb","name":"app","change":{"after":{"name":"app","internal":false}}},
	    {"address":"aws_security_group.alb","mode":"managed","type":"aws_security_group","name":"alb","change":{"after":{"ingress":[{"from_port":80,"to_port":80,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]}}},
	    {"address":"aws_lb_target_group.app","mode":"managed","type":"aws_lb_target_group","name":"app","change":{"after":{"name":"app","port":80,"protocol":"HTTP","target_type":"ip"}}},
	    {"address":"aws_lb_listener.http","mode":"managed","type":"aws_lb_listener","name":"http","change":{"after":{"port":80,"protocol":"HTTP","default_action":[{"type":"forward","target_group_arn":"arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x"}]}}},
	    {"address":"module.x.aws_lb_target_group.app","mode":"managed","type":"aws_lb_target_group","name":"app","change":{"after":{"name":"app","port":80,"protocol":"HTTP","target_type":"ip"}}},
	    {"address":"module.x.aws_ecs_service.app","mode":"managed","type":"aws_ecs_service","name":"app","change":{"after":{"name":"app","load_balancer":[{"target_group_arn":"arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/mod/x","container_name":"app","container_port":8080}]}}},
	    {"address":"module.x.aws_ecs_task_definition.app","mode":"managed","type":"aws_ecs_task_definition","name":"app","change":{"after":{"family":"app","container_definitions":"[{\"name\":\"app\",\"image\":\"app:1\"}]"}}}
	  ],
	  "configuration":{"root_module":{
	    "resources":[
	      {"address":"aws_lb.app","type":"aws_lb","name":"app","mode":"managed","expressions":{"security_groups":{"references":["aws_security_group.alb.id","aws_security_group.alb"]}}},
	      {"address":"aws_security_group.alb","type":"aws_security_group","name":"alb","mode":"managed","expressions":{}},
	      {"address":"aws_lb_target_group.app","type":"aws_lb_target_group","name":"app","mode":"managed","expressions":{}},
	      {"address":"aws_lb_listener.http","type":"aws_lb_listener","name":"http","mode":"managed","expressions":{
	        "load_balancer_arn":{"references":["aws_lb.app.arn","aws_lb.app"]},
	        "default_action":[{"type":{"constant_value":"forward"},"target_group_arn":{"references":["aws_lb_target_group.app.arn","aws_lb_target_group.app"]}}]
	      }}
	    ],
	    "module_calls":{"x":{"expressions":{},"module":{
	      "resources":[
	        {"address":"aws_lb_target_group.app","type":"aws_lb_target_group","name":"app","mode":"managed","expressions":{}},
	        {"address":"aws_ecs_service.app","type":"aws_ecs_service","name":"app","mode":"managed","expressions":{
	          "task_definition":{"references":["aws_ecs_task_definition.app.arn","aws_ecs_task_definition.app"]},
	          "load_balancer":[{"target_group_arn":{"references":["aws_lb_target_group.app.arn","aws_lb_target_group.app"]},"container_name":{"constant_value":"app"},"container_port":{"constant_value":8080}}]
	        }},
	        {"address":"aws_ecs_task_definition.app","type":"aws_ecs_task_definition","name":"app","mode":"managed","expressions":{}}
	      ]
	    }}}
	  }}
	}`)

	doc, _, err := Parse(plan, cfg, "", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lb := findKind(doc, "load_balancer")
	if lb.Kind != "load_balancer" {
		t.Fatal("want load_balancer")
	}
	var modSvc *Element
	for i := range doc.Elements {
		el := &doc.Elements[i]
		if el.Kind == "container_service" && len(el.Evidence.Addresses) == 1 &&
			el.Evidence.Addresses[0] == "module.x.aws_ecs_service.app" {
			modSvc = el
		}
	}
	if modSvc == nil {
		t.Fatal("want module.x container_service")
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.From == lb.ID && f.To == modSvc.ID {
			t.Fatal("root LB must not front module.x service via relative TG name")
		}
	}
}

func TestModuleALBAmbiguousServices(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/module-alb-ambig", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	// terraform-aws-modules/alb shape: two sibling modules both reference
	// target_groups["app"] → ambiguous (warn, no LB→ECS flows).
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"module.alb.aws_lb.this[0]","mode":"managed","type":"aws_lb","name":"this","change":{"after":{"name":"alb","internal":false}}},
	    {"address":"aws_security_group.alb","mode":"managed","type":"aws_security_group","name":"alb","change":{"after":{"ingress":[{"from_port":80,"to_port":80,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]}}},
	    {"address":"module.alb.aws_lb_target_group.this[\"app\"]","mode":"managed","type":"aws_lb_target_group","name":"this","change":{"after":{"name":"app","port":80,"protocol":"HTTP"}}},
	    {"address":"module.alb.aws_lb_listener.this[\"http\"]","mode":"managed","type":"aws_lb_listener","name":"this","change":{"after":{"port":80,"protocol":"HTTP"}}},
	    {"address":"module.svc_a.aws_ecs_service.app","mode":"managed","type":"aws_ecs_service","name":"app","change":{"after":{"name":"a"}}},
	    {"address":"module.svc_a.aws_ecs_task_definition.app","mode":"managed","type":"aws_ecs_task_definition","name":"app","change":{"after":{"family":"a","container_definitions":"[{\"name\":\"app\",\"image\":\"a:1\"}]"}}},
	    {"address":"module.svc_b.aws_ecs_service.app","mode":"managed","type":"aws_ecs_service","name":"app","change":{"after":{"name":"b"}}},
	    {"address":"module.svc_b.aws_ecs_task_definition.app","mode":"managed","type":"aws_ecs_task_definition","name":"app","change":{"after":{"family":"b","container_definitions":"[{\"name\":\"app\",\"image\":\"b:1\"}]"}}}
	  ],
	  "configuration":{"root_module":{
	    "resources":[
	      {"address":"aws_security_group.alb","type":"aws_security_group","name":"alb","mode":"managed","expressions":{}}
	    ],
	    "module_calls":{
	      "alb":{"expressions":{
	        "listeners":{"constant_value":{"http":{"forward":{"target_group_key":"app"},"port":80,"protocol":"HTTP"}}},
	        "security_group_ingress_rules":{"constant_value":{}},
	        "security_groups":{"references":["aws_security_group.alb.id","aws_security_group.alb"]}
	      },"module":{
	        "resources":[
	          {"address":"aws_lb.this[0]","type":"aws_lb","name":"this","mode":"managed","expressions":{"security_groups":{"references":["aws_security_group.alb.id","aws_security_group.alb"]}}},
	          {"address":"aws_lb_target_group.this[\"app\"]","type":"aws_lb_target_group","name":"this","mode":"managed","expressions":{}},
	          {"address":"aws_lb_listener.this[\"http\"]","type":"aws_lb_listener","name":"this","mode":"managed","expressions":{}}
	        ]
	      }},
	      "svc_a":{"expressions":{
	        "target_group_arn":{"references":["module.alb.target_groups[\"app\"].arn","module.alb.target_groups[\"app\"]","module.alb"]}
	      },"module":{
	        "resources":[
	          {"address":"aws_ecs_service.app","type":"aws_ecs_service","name":"app","mode":"managed","expressions":{"task_definition":{"references":["aws_ecs_task_definition.app.arn","aws_ecs_task_definition.app"]}}},
	          {"address":"aws_ecs_task_definition.app","type":"aws_ecs_task_definition","name":"app","mode":"managed","expressions":{}}
	        ]
	      }},
	      "svc_b":{"expressions":{
	        "target_group_arn":{"references":["module.alb.target_groups[\"app\"].arn","module.alb.target_groups[\"app\"]","module.alb"]}
	      },"module":{
	        "resources":[
	          {"address":"aws_ecs_service.app","type":"aws_ecs_service","name":"app","mode":"managed","expressions":{"task_definition":{"references":["aws_ecs_task_definition.app.arn","aws_ecs_task_definition.app"]}}},
	          {"address":"aws_ecs_task_definition.app","type":"aws_ecs_task_definition","name":"app","mode":"managed","expressions":{}}
	        ]
	      }}
	    }
	  }}
	}`)

	doc, warnings, err := Parse(plan, cfg, "", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous service behind module.alb.aws_lb.this[0]") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ambiguous service warning, got %v", warnings)
	}
	lb := findKind(doc, "load_balancer")
	if lb.Kind != "load_balancer" {
		t.Fatal("want load_balancer")
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.From != lb.ID {
			continue
		}
		for j := range doc.Elements {
			el := &doc.Elements[j]
			if el.ID == f.To && el.Kind == "container_service" {
				t.Fatalf("ambiguous module ALB must not emit LB→ECS flow to %s", el.Evidence.Addresses)
			}
		}
	}
}
