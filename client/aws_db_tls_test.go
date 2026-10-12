package client

import "testing"

func TestDBTLSEnforced(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (planResource, []planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "pg16 default group → true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "engine_version": "16.3", "parameter_group_name": "default.postgres16"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "pg14 default → false",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "engine_version": "14.12", "parameter_group_name": "default.postgres14"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "pg14 custom force_ssl=1 → true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "engine_version": "14.12", "parameter_group_name": "app-pg14"},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "aws_db_parameter_group.app",
					values: map[string]any{
						"name": "app-pg14",
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "1"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "pg16 custom force_ssl=0 → false",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "engine_version": "16", "parameter_group_name": "app-pg16"},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "aws_db_parameter_group.app",
					values: map[string]any{
						"name": "app-pg16",
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "0"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "mysql custom require_secure_transport=ON → true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "mysql", "engine_version": "8.0", "parameter_group_name": "app-mysql"},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "aws_db_parameter_group.app",
					values: map[string]any{
						"name": "app-mysql",
						"parameter": []any{map[string]any{"name": "require_secure_transport", "value": "ON"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "mysql default → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "mysql", "engine_version": "8.0", "parameter_group_name": "default.mysql8.0"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "aurora-postgresql cluster group force_ssl=1 → true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_rds_cluster", address: "aws_rds_cluster.db",
					values: map[string]any{
						"engine": "aurora-postgresql", "engine_version": "15.4",
						"db_cluster_parameter_group_name": "app-aurora",
					},
				}
				pg := planResource{
					typ: "aws_rds_cluster_parameter_group", address: "aws_rds_cluster_parameter_group.app",
					values: map[string]any{
						"name": "app-aurora",
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "1"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "aurora default → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_rds_cluster", address: "aws_rds_cluster.db",
					values: map[string]any{
						"engine": "aurora-postgresql", "engine_version": "15.4",
						"db_cluster_parameter_group_name": "default.aurora-postgresql15",
					},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "unresolvable group → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_db_instance.db": {refs: map[string][]string{
						"parameter_group_name": {"var.parameter_group_name"},
					}},
				}}
				return db, []planResource{db}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "engine_version unknown → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "parameter_group_name": "default.postgres16"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "direct config ref to managed group",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values:       map[string]any{"engine": "postgres", "engine_version": "14"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "aws_db_parameter_group.app",
					values: map[string]any{
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "true"}},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_db_instance.db": {refs: map[string][]string{
						"parameter_group_name": {"aws_db_parameter_group.app.id", "aws_db_parameter_group.app"},
					}},
				}}
				return db, []planResource{db, pg}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "no group absent pg16 → true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "postgres", "engine_version": "16"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "known name matching planned group → resolved",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{
						"engine": "postgres", "engine_version": "14",
						"parameter_group_name": "app-pg14",
					},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "aws_db_parameter_group.app",
					values: map[string]any{
						"name": "app-pg14",
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "1"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "known external name not in plan → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.aws_db_instance.this[0]",
					values: map[string]any{
						"engine": "postgres", "engine_version": "16",
						"parameter_group_name": "external-elsewhere",
					},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "module.db.aws_db_parameter_group.this[0]",
					values: map[string]any{"name": "other", "parameter": []any{}},
				}
				// Sibling group must not be used when planned name is known.
				idx := configIndex{resources: map[string]exprSet{
					"module.db.aws_db_instance.this": {refs: map[string][]string{
						"parameter_group_name": {"local.parameter_group_name_id"},
					}},
				}}
				return db, []planResource{db, pg}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "known default.postgres16 → default rule true",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{
						"engine": "postgres", "engine_version": "16",
						"parameter_group_name": "default.postgres16",
					},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "unknown + local + one group in subtree → resolved",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.module.db_instance.aws_db_instance.this[0]",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "module.db.module.db_parameter_group.aws_db_parameter_group.this[0]",
					values:       map[string]any{"family": "postgres16", "name_prefix": "app-", "parameter": []any{}},
					afterUnknown: map[string]any{"name": true},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"module.db.module.db_instance.aws_db_instance.this": {refs: map[string][]string{
							"parameter_group_name": {"var.parameter_group_name"},
						}},
					},
					calls: map[string]exprSet{
						"module.db.module.db_instance": {refs: map[string][]string{
							"parameter_group_name": {"local.parameter_group_name_id"},
						}},
					},
				}
				return db, []planResource{db, pg}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "unknown + local + two groups → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.module.db_instance.aws_db_instance.this[0]",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				pgA := planResource{
					typ: "aws_db_parameter_group", address: "module.db.aws_db_parameter_group.a",
					values:       map[string]any{"parameter": []any{}},
					afterUnknown: map[string]any{"name": true},
				}
				pgB := planResource{
					typ: "aws_db_parameter_group", address: "module.db.aws_db_parameter_group.b",
					values:       map[string]any{"parameter": []any{}},
					afterUnknown: map[string]any{"name": true},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"module.db.module.db_instance.aws_db_instance.this": {refs: map[string][]string{
							"parameter_group_name": {"var.parameter_group_name"},
						}},
					},
					calls: map[string]exprSet{
						"module.db.module.db_instance": {refs: map[string][]string{
							"parameter_group_name": {"local.parameter_group_name_id"},
						}},
					},
				}
				return db, []planResource{db, pgA, pgB}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "unknown + local + zero groups → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.module.db_instance.aws_db_instance.this[0]",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"module.db.module.db_instance.aws_db_instance.this": {refs: map[string][]string{
							"parameter_group_name": {"var.parameter_group_name"},
						}},
					},
					calls: map[string]exprSet{
						"module.db.module.db_instance": {refs: map[string][]string{
							"parameter_group_name": {"local.parameter_group_name_id"},
						}},
					},
				}
				return db, []planResource{db}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "rds-shaped try() create=true → resolved (direct group ref)",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.module.db_instance.aws_db_instance.this[0]",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "module.db.module.db_parameter_group.aws_db_parameter_group.this[0]",
					values: map[string]any{"family": "postgres16", "parameter": []any{}},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"module.db.module.db_instance.aws_db_instance.this": {refs: map[string][]string{
							"parameter_group_name": {"var.parameter_group_name"},
						}},
					},
					calls: map[string]exprSet{
						"module.db": {constants: map[string]any{"create_db_parameter_group": true}},
						"module.db.module.db_instance": {refs: map[string][]string{
							"parameter_group_name": {
								"aws_db_parameter_group.this[0].name",
								"aws_db_parameter_group.this[0]",
								"var.parameter_group_name",
							},
						}},
					},
				}
				return db, []planResource{db, pg}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "ternary managed group + unknown external → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.aws_db_instance.this[0]",
					values:       map[string]any{"engine": "postgres", "engine_version": "16"},
					afterUnknown: map[string]any{"parameter_group_name": true},
				}
				pg := planResource{
					typ: "aws_db_parameter_group", address: "module.db.aws_db_parameter_group.app",
					values: map[string]any{"parameter": []any{}},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"module.db.aws_db_instance.this": {refs: map[string][]string{
							"parameter_group_name": {
								"aws_db_parameter_group.app.name",
								"var.external_name",
							},
						}},
					},
					calls: map[string]exprSet{"module.db": {}},
				}
				return db, []planResource{db, pg}, idx
			},
			wantVal: false, wantKnown: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, resources, idx := tc.build()
			got, known := dbTLSEnforced(db, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}
