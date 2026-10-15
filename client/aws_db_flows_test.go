package client

import (
	"encoding/json"
	"strings"
	"testing"
)

// rootFlatDBPlan: app + worker ECS → one RDS via aws_security_group.db.
// App: data-doc rds-db:connect scoped via resource_id ref; worker: "*".
func rootFlatDBPlan(t *testing.T, sharedSG bool, useVPCIngressRule bool) string {
	t.Helper()
	appSGName := "app"
	workerSGName := "worker"
	if sharedSG {
		appSGName = "ecs"
		workerSGName = "ecs"
	}

	sgResources := []map[string]any{
		rcSG(appSGName),
	}
	if !sharedSG {
		sgResources = append(sgResources, rcSG(workerSGName))
	}
	sgResources = append(sgResources, map[string]any{
		"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
		"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
			"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
		}},
	})

	resources := append(sgResources,
		map[string]any{
			"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"identifier": "main", "engine": "postgres", "engine_version": "16",
				"publicly_accessible": false, "storage_encrypted": true, "deletion_protection": false,
			}, "after_unknown": map[string]any{
				"resource_id": true, "parameter_group_name": true, "vpc_security_group_ids": true,
			}},
		},
		map[string]any{
			"address": "aws_iam_role.ecs_task", "mode": "managed", "type": "aws_iam_role", "name": "ecs_task",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "task"}},
		},
		map[string]any{
			"address": "aws_iam_role.ecs_task_worker", "mode": "managed", "type": "aws_iam_role", "name": "ecs_task_worker",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "worker"}},
		},
		map[string]any{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family": "app", "container_definitions": `[{"name":"app","image":"app:1"}]`,
			}, "after_unknown": map[string]any{"task_role_arn": true}},
		},
		map[string]any{
			"address": "aws_ecs_task_definition.worker", "mode": "managed", "type": "aws_ecs_task_definition", "name": "worker",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family": "worker", "container_definitions": `[{"name":"worker","image":"app:1"}]`,
			}, "after_unknown": map[string]any{"task_role_arn": true}},
		},
		map[string]any{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		map[string]any{
			"address": "aws_ecs_service.worker", "mode": "managed", "type": "aws_ecs_service", "name": "worker",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "worker"}},
		},
		map[string]any{
			"address": "data.aws_iam_policy_document.app_rds", "mode": "data", "type": "aws_iam_policy_document", "name": "app_rds",
			"change": map[string]any{"actions": []any{"read"}, "after": map[string]any{
				"statement": []any{map[string]any{
					"effect": "Allow", "actions": []any{"rds-db:connect"}, "resources": []any{nil},
				}},
			}},
		},
		map[string]any{
			"address": "data.aws_iam_policy_document.worker_rds", "mode": "data", "type": "aws_iam_policy_document", "name": "worker_rds",
			"change": map[string]any{"actions": []any{"read"}, "after": map[string]any{
				"statement": []any{map[string]any{
					"effect": "Allow", "actions": []any{"rds-db:connect"}, "resources": []any{"*"},
				}},
			}},
		},
		map[string]any{
			"address": "aws_iam_role_policy.app_rds", "mode": "managed", "type": "aws_iam_role_policy", "name": "app_rds",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app-rds"},
				"after_unknown": map[string]any{"policy": true}},
		},
		map[string]any{
			"address": "aws_iam_role_policy.worker_rds", "mode": "managed", "type": "aws_iam_role_policy", "name": "worker_rds",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "worker-rds"},
				"after_unknown": map[string]any{"policy": true}},
		},
	)

	cfg := []map[string]any{
		cfgSG(appSGName),
	}
	if !sharedSG {
		cfg = append(cfg, cfgSG(workerSGName))
	}

	ingressRefs := []any{"aws_security_group." + appSGName + ".id", "aws_security_group." + appSGName}
	if !sharedSG {
		ingressRefs = append(ingressRefs,
			"aws_security_group."+workerSGName+".id", "aws_security_group."+workerSGName)
	}

	dbSGExpr := map[string]any{}
	if !useVPCIngressRule {
		dbSGExpr["ingress"] = map[string]any{"references": ingressRefs}
	}
	cfg = append(cfg,
		map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": dbSGExpr},
		map[string]any{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{
			"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
		}},
		map[string]any{"address": "aws_iam_role.ecs_task", "type": "aws_iam_role", "name": "ecs_task", "expressions": map[string]any{}},
		map[string]any{"address": "aws_iam_role.ecs_task_worker", "type": "aws_iam_role", "name": "ecs_task_worker", "expressions": map[string]any{}},
		map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": map[string]any{
			"task_role_arn": map[string]any{"references": []any{"aws_iam_role.ecs_task.arn", "aws_iam_role.ecs_task"}},
		}},
		map[string]any{"address": "aws_ecs_task_definition.worker", "type": "aws_ecs_task_definition", "name": "worker", "expressions": map[string]any{
			"task_role_arn": map[string]any{"references": []any{"aws_iam_role.ecs_task_worker.arn", "aws_iam_role.ecs_task_worker"}},
		}},
		map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": map[string]any{
			"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
			"network_configuration": map[string]any{"references": []any{
				"aws_security_group." + appSGName + ".id", "aws_security_group." + appSGName,
			}},
		}},
		map[string]any{"address": "aws_ecs_service.worker", "type": "aws_ecs_service", "name": "worker", "expressions": map[string]any{
			"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.worker.arn", "aws_ecs_task_definition.worker"}},
			"network_configuration": map[string]any{"references": []any{
				"aws_security_group." + workerSGName + ".id", "aws_security_group." + workerSGName,
			}},
		}},
		map[string]any{"address": "data.aws_iam_policy_document.app_rds", "type": "aws_iam_policy_document", "name": "app_rds", "mode": "data",
			"expressions": map[string]any{
				"statement": map[string]any{"references": []any{"aws_db_instance.main.resource_id", "aws_db_instance.main"}},
			}},
		map[string]any{"address": "data.aws_iam_policy_document.worker_rds", "type": "aws_iam_policy_document", "name": "worker_rds", "mode": "data",
			"expressions": map[string]any{}},
		map[string]any{"address": "aws_iam_role_policy.app_rds", "type": "aws_iam_role_policy", "name": "app_rds", "expressions": map[string]any{
			"role":   map[string]any{"references": []any{"aws_iam_role.ecs_task.id", "aws_iam_role.ecs_task"}},
			"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.app_rds.json", "data.aws_iam_policy_document.app_rds"}},
		}},
		map[string]any{"address": "aws_iam_role_policy.worker_rds", "type": "aws_iam_role_policy", "name": "worker_rds", "expressions": map[string]any{
			"role":   map[string]any{"references": []any{"aws_iam_role.ecs_task_worker.id", "aws_iam_role.ecs_task_worker"}},
			"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.worker_rds.json", "data.aws_iam_policy_document.worker_rds"}},
		}},
	)

	if useVPCIngressRule {
		peers := []string{appSGName}
		if !sharedSG {
			peers = append(peers, workerSGName)
		}
		for _, peer := range peers {
			name := peer
			resources = append(resources, map[string]any{
				"address": "aws_vpc_security_group_ingress_rule." + name, "mode": "managed",
				"type": "aws_vpc_security_group_ingress_rule", "name": name,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"from_port": 5432, "to_port": 5432, "ip_protocol": "tcp",
					"referenced_security_group_id": nil,
				}, "after_unknown": map[string]any{"referenced_security_group_id": true, "security_group_id": true}},
			})
			cfg = append(cfg, map[string]any{
				"address": "aws_vpc_security_group_ingress_rule." + name, "type": "aws_vpc_security_group_ingress_rule", "name": name,
				"expressions": map[string]any{
					"security_group_id": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
					"referenced_security_group_id": map[string]any{"references": []any{
						"aws_security_group." + peer + ".id", "aws_security_group." + peer,
					}},
				},
			})
		}
	}

	raw, err := json.Marshal(map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func rcSG(name string) map[string]any {
	return map[string]any{
		"address": "aws_security_group." + name, "mode": "managed", "type": "aws_security_group", "name": name,
		"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
	}
}

func cfgSG(name string) map[string]any {
	return map[string]any{
		"address": "aws_security_group." + name, "type": "aws_security_group", "name": name, "expressions": map[string]any{},
	}
}

func dbFlowsFromPlan(t *testing.T, plan string) (DFD, []string) {
	t.Helper()
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/db-flows", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func dbFlowScopes(doc DFD) map[string]string {
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	out := map[string]string{}
	for _, f := range doc.Flows {
		to := byID[f.To]
		from := byID[f.From]
		if to.Kind != "relational_db" {
			continue
		}
		fromAddr := ""
		if len(from.Evidence.Addresses) == 1 {
			fromAddr = from.Evidence.Addresses[0]
		}
		out[fromAddr] = f.AuthzScope
	}
	return out
}

func TestRootFlatDBFlowsTwoServices(t *testing.T) {
	doc, warnings := dbFlowsFromPlan(t, rootFlatDBPlan(t, false, false))
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous database") {
			t.Fatalf("unexpected ambiguous warning: %v", warnings)
		}
	}
	scopes := dbFlowScopes(doc)
	if len(scopes) != 2 {
		t.Fatalf("db flows=%d want 2: %#v", len(scopes), scopes)
	}
	if scopes["aws_ecs_service.app"] != "resource" {
		t.Fatalf("app scope=%q want resource", scopes["aws_ecs_service.app"])
	}
	if scopes["aws_ecs_service.worker"] != "account" {
		t.Fatalf("worker scope=%q want account", scopes["aws_ecs_service.worker"])
	}
	for _, el := range doc.Elements {
		if el.Kind != "relational_db" {
			continue
		}
		if el.Attributes["tls_enforced"] != true {
			t.Fatalf("tls_enforced=%v want true", el.Attributes["tls_enforced"])
		}
	}
}

func TestRootFlatDBFlowsVPCIngressRule(t *testing.T) {
	doc, warnings := dbFlowsFromPlan(t, rootFlatDBPlan(t, false, true))
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous database") {
			t.Fatalf("unexpected ambiguous: %v", warnings)
		}
	}
	scopes := dbFlowScopes(doc)
	if len(scopes) != 2 {
		t.Fatalf("db flows=%d want 2: %#v", len(scopes), scopes)
	}
}

func TestRootFlatDBFlowsSharedSG(t *testing.T) {
	doc, _ := dbFlowsFromPlan(t, rootFlatDBPlan(t, true, false))
	scopes := dbFlowScopes(doc)
	if len(scopes) != 2 {
		t.Fatalf("shared SG must yield two flows, got %#v", scopes)
	}
}

func TestDBFlowsNoCrossModuleSGName(t *testing.T) {
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
				}},
			},
			map[string]any{
				"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"identifier": "main", "engine": "postgres", "engine_version": "16",
				}, "after_unknown": map[string]any{"vpc_security_group_ids": true}},
			},
			map[string]any{
				"address": "module.other.aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"module_address": "module.other",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "module.other.aws_ecs_service.this", "mode": "managed", "type": "aws_ecs_service", "name": "this",
				"module_address": "module.other",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "other"}},
			},
			map[string]any{
				"address": "module.other.aws_ecs_task_definition.this", "mode": "managed", "type": "aws_ecs_task_definition", "name": "this",
				"module_address": "module.other",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "x", "container_definitions": `[{"name":"x","image":"x:1"}]`,
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_security_group.app", "type": "aws_security_group", "name": "app", "expressions": map[string]any{}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
					map[string]any{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
					}},
				},
				"module_calls": map[string]any{
					"other": map[string]any{
						"source":      "./other",
						"expressions": map[string]any{},
						"module": map[string]any{
							"resources": []any{
								// Same local name "db" as the root SG — must not link to root DB.
								map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{}},
								map[string]any{"address": "aws_ecs_service.this", "type": "aws_ecs_service", "name": "this", "expressions": map[string]any{
									"network_configuration": map[string]any{"references": []any{
										"aws_security_group.db.id", "aws_security_group.db",
									}},
									"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.this.arn"}},
								}},
								map[string]any{"address": "aws_ecs_task_definition.this", "type": "aws_ecs_task_definition", "name": "this", "expressions": map[string]any{}},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := dbFlowsFromPlan(t, string(raw))
	for from := range dbFlowScopes(doc) {
		if strings.HasPrefix(from, "module.other.") {
			t.Fatalf("cross-module link to %s", from)
		}
	}
}

func TestDBFlowsPeerSameModuleOnly(t *testing.T) {
	// Root DB SG ingress refs aws_security_group.app; module.x also has
	// aws_security_group.app + an ECS service using it — only the root
	// service is linked (peer match is same-module).
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
				}},
			},
			map[string]any{
				"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"identifier": "main", "engine": "postgres", "engine_version": "16",
				}, "after_unknown": map[string]any{"vpc_security_group_ids": true}},
			},
			map[string]any{
				"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "task"}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "app", "container_definitions": `[{"name":"app","image":"app:1"}]`,
				}, "after_unknown": map[string]any{"task_role_arn": true}},
			},
			map[string]any{
				"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "module.x.aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
				"module_address": "module.x",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "module.x.aws_ecs_service.this", "mode": "managed", "type": "aws_ecs_service", "name": "this",
				"module_address": "module.x",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "x"}},
			},
			map[string]any{
				"address": "module.x.aws_ecs_task_definition.this", "mode": "managed", "type": "aws_ecs_task_definition", "name": "this",
				"module_address": "module.x",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "x", "container_definitions": `[{"name":"x","image":"x:1"}]`,
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_security_group.app", "type": "aws_security_group", "name": "app", "expressions": map[string]any{}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
					map[string]any{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
					}},
					map[string]any{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{}},
					map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": map[string]any{
						"task_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
					}},
					map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": map[string]any{
						"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
						"network_configuration": map[string]any{"references": []any{
							"aws_security_group.app.id", "aws_security_group.app",
						}},
					}},
				},
				"module_calls": map[string]any{
					"x": map[string]any{
						"source":      "./x",
						"expressions": map[string]any{},
						"module": map[string]any{"resources": []any{
							map[string]any{"address": "aws_security_group.app", "type": "aws_security_group", "name": "app", "expressions": map[string]any{}},
							map[string]any{"address": "aws_ecs_service.this", "type": "aws_ecs_service", "name": "this", "expressions": map[string]any{
								"network_configuration": map[string]any{"references": []any{
									"aws_security_group.app.id", "aws_security_group.app",
								}},
								"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.this.arn"}},
							}},
							map[string]any{"address": "aws_ecs_task_definition.this", "type": "aws_ecs_task_definition", "name": "this", "expressions": map[string]any{}},
						}},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings := dbFlowsFromPlan(t, string(raw))
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous database") {
			t.Fatalf("unexpected ambiguous: %v", warnings)
		}
	}
	scopes := dbFlowScopes(doc)
	if len(scopes) != 1 {
		t.Fatalf("want exactly one db flow (root app), got %#v", scopes)
	}
	if _, ok := scopes["aws_ecs_service.app"]; !ok {
		t.Fatalf("want root aws_ecs_service.app, got %#v", scopes)
	}
	for from := range scopes {
		if strings.HasPrefix(from, "module.x.") {
			t.Fatalf("module.x must not link: %#v", scopes)
		}
	}
}

func TestDBFlowsModulePeerTwoServicesAmbiguous(t *testing.T) {
	// One peer SG passed into a module containing two ECS services →
	// ambiguous warning, no flows from that module.
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_security_group.tasks", "mode": "managed", "type": "aws_security_group", "name": "tasks",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
				}},
			},
			map[string]any{
				"address": "module.db.aws_db_instance.this", "mode": "managed", "type": "aws_db_instance", "name": "this",
				"module_address": "module.db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"identifier": "main", "engine": "postgres", "engine_version": "16",
				}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_service.a", "mode": "managed", "type": "aws_ecs_service", "name": "a",
				"module_address": "module.ecs",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "a"}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_service.b", "mode": "managed", "type": "aws_ecs_service", "name": "b",
				"module_address": "module.ecs",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "b"}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_task_definition.a", "mode": "managed", "type": "aws_ecs_task_definition", "name": "a",
				"module_address": "module.ecs",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "a", "container_definitions": `[{"name":"a","image":"a:1"}]`,
				}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_task_definition.b", "mode": "managed", "type": "aws_ecs_task_definition", "name": "b",
				"module_address": "module.ecs",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "b", "container_definitions": `[{"name":"b","image":"b:1"}]`,
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_security_group.tasks", "type": "aws_security_group", "name": "tasks", "expressions": map[string]any{}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
					}},
				},
				"module_calls": map[string]any{
					"ecs": map[string]any{
						"source": "./ecs",
						"expressions": map[string]any{
							"security_group_ids": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
						},
						"module": map[string]any{"resources": []any{
							map[string]any{"address": "aws_ecs_service.a", "type": "aws_ecs_service", "name": "a", "expressions": map[string]any{
								"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.a.arn"}},
							}},
							map[string]any{"address": "aws_ecs_service.b", "type": "aws_ecs_service", "name": "b", "expressions": map[string]any{
								"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.b.arn"}},
							}},
							map[string]any{"address": "aws_ecs_task_definition.a", "type": "aws_ecs_task_definition", "name": "a", "expressions": map[string]any{}},
							map[string]any{"address": "aws_ecs_task_definition.b", "type": "aws_ecs_task_definition", "name": "b", "expressions": map[string]any{}},
						}},
					},
					"db": map[string]any{
						"source": "./db",
						"expressions": map[string]any{
							"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
						},
						"module": map[string]any{"resources": []any{
							map[string]any{"address": "aws_db_instance.this", "type": "aws_db_instance", "name": "this", "expressions": map[string]any{}},
						}},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings := dbFlowsFromPlan(t, string(raw))
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous database path through aws_security_group.db") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ambiguous module-source warning, got %v", warnings)
	}
	if scopes := dbFlowScopes(doc); len(scopes) != 0 {
		t.Fatalf("ambiguous module peer must yield no db flows: %#v", scopes)
	}
}

func TestDBFlowsAmbiguousMultipleDestinations(t *testing.T) {
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_security_group.tasks", "mode": "managed", "type": "aws_security_group", "name": "tasks",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
				}},
			},
			map[string]any{
				"address": "module.db.aws_db_instance.a", "mode": "managed", "type": "aws_db_instance", "name": "a",
				"module_address": "module.db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"identifier": "a", "engine": "postgres", "engine_version": "16",
				}},
			},
			map[string]any{
				"address": "module.db.aws_db_instance.b", "mode": "managed", "type": "aws_db_instance", "name": "b",
				"module_address": "module.db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"identifier": "b", "engine": "postgres", "engine_version": "16",
				}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_service.this", "mode": "managed", "type": "aws_ecs_service", "name": "this",
				"module_address": "module.ecs",
				"change":         map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "module.ecs.aws_ecs_task_definition.this", "mode": "managed", "type": "aws_ecs_task_definition", "name": "this",
				"module_address": "module.ecs",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "app", "container_definitions": `[{"name":"app","image":"app:1"}]`,
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_security_group.tasks", "type": "aws_security_group", "name": "tasks", "expressions": map[string]any{}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
					}},
				},
				"module_calls": map[string]any{
					"ecs": map[string]any{
						"source": "./ecs",
						"expressions": map[string]any{
							"security_group_ids": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
						},
						"module": map[string]any{"resources": []any{
							map[string]any{"address": "aws_ecs_service.this", "type": "aws_ecs_service", "name": "this", "expressions": map[string]any{
								"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.this.arn"}},
							}},
							map[string]any{"address": "aws_ecs_task_definition.this", "type": "aws_ecs_task_definition", "name": "this", "expressions": map[string]any{}},
						}},
					},
					"db": map[string]any{
						"source": "./db",
						"expressions": map[string]any{
							"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
						},
						"module": map[string]any{"resources": []any{
							map[string]any{"address": "aws_db_instance.a", "type": "aws_db_instance", "name": "a", "expressions": map[string]any{}},
							map[string]any{"address": "aws_db_instance.b", "type": "aws_db_instance", "name": "b", "expressions": map[string]any{}},
						}},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings := dbFlowsFromPlan(t, string(raw))
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous database path through aws_security_group.db") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ambiguous destination warning, got %v", warnings)
	}
	if scopes := dbFlowScopes(doc); len(scopes) != 0 {
		t.Fatalf("ambiguous dest must yield no db flows: %#v", scopes)
	}
}
