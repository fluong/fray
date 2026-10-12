package client

import "testing"

func TestResolveModuleOutputSecurityGroup(t *testing.T) {
	src := Source{Repo: "a/b", Commit: "x", Tool: "terraform", Fidelity: "plan"}
	plainCfg := []byte("schema_version: fray-config/v1\n")

	t.Run("output → aws_security_group.this.id → resolved", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.sg.aws_security_group.this","mode":"managed","type":"aws_security_group","change":{"after":{"name":"app","ingress":[{"from_port":5432,"to_port":5432,"protocol":"tcp","security_groups":["sg-peer"],"cidr_blocks":[]}]}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["module.sg.security_group_id","module.sg"]}
		      }}
		    ],
		    "module_calls":{"sg":{"expressions":{},"module":{
		      "resources":[{"address":"aws_security_group.this","type":"aws_security_group","name":"this","mode":"managed","expressions":{}}],
		      "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		db := findKind(doc, "relational_db")
		if db.Attributes["network_restricted"] != true {
			t.Fatalf("network_restricted=%#v want true", db.Attributes["network_restricted"])
		}
	})

	t.Run("nested module two levels → resolved", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.edge.module.sg.aws_security_group.this","mode":"managed","type":"aws_security_group","change":{"after":{"name":"app","ingress":[{"from_port":5432,"to_port":5432,"protocol":"tcp","security_groups":["sg-peer"],"cidr_blocks":[]}]}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["module.edge.sg_id","module.edge"]}
		      }}
		    ],
		    "module_calls":{"edge":{"expressions":{},"module":{
		      "outputs":{"sg_id":{"expression":{"references":["module.sg.security_group_id","module.sg"]}}},
		      "module_calls":{"sg":{"expressions":{},"module":{
		        "resources":[{"address":"aws_security_group.this","type":"aws_security_group","name":"this","mode":"managed","expressions":{}}],
		        "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
		      }}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findKind(doc, "relational_db").Attributes["network_restricted"] != true {
			t.Fatalf("want network_restricted true")
		}
	})

	t.Run("output var passthrough from root direct ref → resolved", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"aws_security_group.app","mode":"managed","type":"aws_security_group","change":{"after":{"name":"app","ingress":[{"from_port":5432,"to_port":5432,"protocol":"tcp","security_groups":["sg-peer"],"cidr_blocks":[]}]}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_security_group.app","type":"aws_security_group","name":"app","mode":"managed","expressions":{}},
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["module.wrap.sg_id","module.wrap"]}
		      }}
		    ],
		    "module_calls":{"wrap":{
		      "expressions":{"security_group_id":{"references":["aws_security_group.app.id","aws_security_group.app"]}},
		      "module":{
		        "outputs":{"sg_id":{"expression":{"references":["var.security_group_id"]}}}
		      }
		    }}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findKind(doc, "relational_db").Attributes["network_restricted"] != true {
			t.Fatalf("want network_restricted true via output var passthrough")
		}
	})

	t.Run("for_each module literal key → resolved", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.sg[\"app\"].aws_security_group.this","mode":"managed","type":"aws_security_group","change":{"after":{"name":"app","ingress":[{"from_port":5432,"to_port":5432,"protocol":"tcp","security_groups":["sg-peer"],"cidr_blocks":[]}]}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["module.sg[\"app\"].security_group_id","module.sg[\"app\"]"]}
		      }}
		    ],
		    "module_calls":{"sg":{"expressions":{},"module":{
		      "resources":[{"address":"aws_security_group.this","type":"aws_security_group","name":"this","mode":"managed","expressions":{}}],
		      "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findKind(doc, "relational_db").Attributes["network_restricted"] != true {
			t.Fatalf("want network_restricted true for for_each key")
		}
	})

	t.Run("output conditional → absent", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.sg.aws_security_group.a","mode":"managed","type":"aws_security_group","change":{"after":{"name":"a","ingress":[]}}},
		    {"address":"module.sg.aws_security_group.b","mode":"managed","type":"aws_security_group","change":{"after":{"name":"b","ingress":[]}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["module.sg.security_group_id","module.sg"]}
		      }}
		    ],
		    "module_calls":{"sg":{"expressions":{},"module":{
		      "resources":[
		        {"address":"aws_security_group.a","type":"aws_security_group","name":"a","mode":"managed","expressions":{}},
		        {"address":"aws_security_group.b","type":"aws_security_group","name":"b","mode":"managed","expressions":{}}
		      ],
		      "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.a.id","aws_security_group.a","aws_security_group.b.id","aws_security_group.b"]}}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := findKind(doc, "relational_db").Attributes["network_restricted"]; ok {
			t.Fatalf("ambiguous output should leave network_restricted absent")
		}
	})

	t.Run("first-apply unknown id direct output ref → resolved peer", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.sg.aws_security_group.this","mode":"managed","type":"aws_security_group","change":{"after":{"name":"app"}}},
		    {"address":"aws_security_group.db","mode":"managed","type":"aws_security_group","change":{"after":{"name":"db","ingress":[]}}},
		    {"address":"aws_vpc_security_group_ingress_rule.peer","mode":"managed","type":"aws_vpc_security_group_ingress_rule","change":{"after":{"from_port":5432,"to_port":5432,"ip_protocol":"tcp","cidr_ipv4":null,"referenced_security_group_id":null},"after_unknown":{"referenced_security_group_id":true}}},
		    {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"db","engine":"postgres","engine_version":"16","vpc_security_group_ids":null,"publicly_accessible":false,"storage_encrypted":true,"deletion_protection":true},"after_unknown":{"vpc_security_group_ids":true}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_security_group.db","type":"aws_security_group","name":"db","mode":"managed","expressions":{}},
		      {"address":"aws_vpc_security_group_ingress_rule.peer","type":"aws_vpc_security_group_ingress_rule","name":"peer","mode":"managed","expressions":{
		        "security_group_id":{"references":["aws_security_group.db.id","aws_security_group.db"]},
		        "referenced_security_group_id":{"references":["module.sg.security_group_id","module.sg"]}
		      }},
		      {"address":"aws_db_instance.db","type":"aws_db_instance","name":"db","mode":"managed","expressions":{
		        "vpc_security_group_ids":{"references":["aws_security_group.db.id","aws_security_group.db"]}
		      }}
		    ],
		    "module_calls":{"sg":{"expressions":{},"module":{
		      "resources":[{"address":"aws_security_group.this","type":"aws_security_group","name":"this","mode":"managed","expressions":{}}],
		      "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findKind(doc, "relational_db").Attributes["network_restricted"] != true {
			t.Fatalf("want network_restricted true via module output peer")
		}
	})

	t.Run("LB security_groups via module output", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"module.sg.aws_security_group.this","mode":"managed","type":"aws_security_group","change":{"after":{"name":"lb","ingress":[{"from_port":80,"to_port":80,"protocol":"tcp","cidr_blocks":["10.0.0.0/8"],"security_groups":[]}]}}},
		    {"address":"aws_lb.app","mode":"managed","type":"aws_lb","change":{"after":{"name":"app","internal":false,"security_groups":null},"after_unknown":{"security_groups":true}}},
		    {"address":"aws_lb_listener.http","mode":"managed","type":"aws_lb_listener","change":{"after":{"port":80,"protocol":"HTTP"}}}
		  ],
		  "configuration": {"root_module":{
		    "resources":[
		      {"address":"aws_lb.app","type":"aws_lb","name":"app","mode":"managed","expressions":{
		        "security_groups":{"references":["module.sg.security_group_id","module.sg"]}
		      }},
		      {"address":"aws_lb_listener.http","type":"aws_lb_listener","name":"http","mode":"managed","expressions":{
		        "load_balancer_arn":{"references":["aws_lb.app.arn","aws_lb.app"]}
		      }}
		    ],
		    "module_calls":{"sg":{"expressions":{},"module":{
		      "resources":[{"address":"aws_security_group.this","type":"aws_security_group","name":"this","mode":"managed","expressions":{}}],
		      "outputs":{"security_group_id":{"expression":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
		    }}}
		  }}
		}`)
		doc, _, err := Parse(plan, plainCfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		lb := findKind(doc, "load_balancer")
		if lb.Attributes["public"] != false {
			t.Fatalf("LB public=%#v want false (private CIDR)", lb.Attributes["public"])
		}
	})
}

func TestParseModuleOutputRef(t *testing.T) {
	cases := []struct {
		ref, mod, out string
		ok            bool
	}{
		{"module.sg.security_group_id", "module.sg", "security_group_id", true},
		{`module.sg["app"].security_group_id`, `module.sg["app"]`, "security_group_id", true},
		{"module.a.module.b.sg_id", "module.a.module.b", "sg_id", true},
		{"module.sg.aws_security_group.this.id", "", "", false},
		{"aws_security_group.this.id", "", "", false},
	}
	for _, tc := range cases {
		mod, out, ok := parseModuleOutputRef(tc.ref)
		if ok != tc.ok || mod != tc.mod || out != tc.out {
			t.Fatalf("%s: got (%q,%q,%v) want (%q,%q,%v)", tc.ref, mod, out, ok, tc.mod, tc.out, tc.ok)
		}
	}
}
