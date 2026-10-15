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
						"name":      "app-pg14",
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
						"name":      "app-pg16",
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
						"name":      "app-mysql",
						"parameter": []any{map[string]any{"name": "require_secure_transport", "value": "ON"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "mysql default → false (documented OFF)",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.db",
					values: map[string]any{"engine": "mysql", "engine_version": "8.0", "parameter_group_name": "default.mysql8.0"},
				}
				return db, []planResource{db}, configIndex{}
			},
			wantVal: false, wantKnown: true,
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
						"name":      "app-aurora",
						"parameter": []any{map[string]any{"name": "rds.force_ssl", "value": "1"}},
					},
				}
				return db, []planResource{db, pg}, configIndex{}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "aurora-postgresql 15 default → false (≤16 OFF)",
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
			wantVal: false, wantKnown: true,
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
						"name":      "app-pg14",
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

// B-03: documented engine defaults when the effective group is default.*
// (same path as postgres ≥15). Documented OFF → false/known, like postgres ≤14.
func TestEngineTLSDefaultB03(t *testing.T) {
	cases := []struct {
		name      string
		typ       string
		engine    string
		version   string
		group     string // parameter / cluster parameter group name
		wantVal   bool
		wantKnown bool
	}{
		// aurora-postgresql (aws_rds_cluster)
		{"aurora-pg 17 → true", "aws_rds_cluster", "aurora-postgresql", "17.1", "default.aurora-postgresql17", true, true},
		{"aurora-pg 16 → false", "aws_rds_cluster", "aurora-postgresql", "16.4", "default.aurora-postgresql16", false, true},
		{"aurora-pg unknown version → omit", "aws_rds_cluster", "aurora-postgresql", "", "default.aurora-postgresql17", false, false},
		{"aurora-pg unparseable → omit", "aws_rds_cluster", "aurora-postgresql", "latest", "default.aurora-postgresql17", false, false},

		// aurora-mysql (aws_rds_cluster)
		{"aurora-mysql 8.4 → true", "aws_rds_cluster", "aurora-mysql", "8.4.0", "default.aurora-mysql8.4", true, true},
		{"aurora-mysql 8.4 vendor string → true", "aws_rds_cluster", "aurora-mysql", "8.4.mysql_aurora.4.0.0", "default.aurora-mysql8.4", true, true},
		{"aurora-mysql 8.0 (v3) → omit", "aws_rds_cluster", "aurora-mysql", "8.0.mysql_aurora.3.08.0", "default.aurora-mysql8.0", false, false},
		{"aurora-mysql 8.0 plain → omit", "aws_rds_cluster", "aurora-mysql", "8.0", "default.aurora-mysql8.0", false, false},
		{"aurora-mysql unknown → omit", "aws_rds_cluster", "aurora-mysql", "", "default.aurora-mysql8.4", false, false},

		// mariadb (aws_db_instance)
		{"mariadb 11.8 → true", "aws_db_instance", "mariadb", "11.8.2", "default.mariadb11.8", true, true},
		{"mariadb 11.4 → false", "aws_db_instance", "mariadb", "11.4.3", "default.mariadb11.4", false, true},
		{"mariadb 10.5 → false", "aws_db_instance", "mariadb", "10.5.0", "default.mariadb10.5", false, true},
		{"mariadb 10.4 → omit", "aws_db_instance", "mariadb", "10.4.0", "default.mariadb10.4", false, false},
		{"mariadb 11.5 → omit", "aws_db_instance", "mariadb", "11.5.0", "default.mariadb11.5", false, false},
		{"mariadb unknown → omit", "aws_db_instance", "mariadb", "", "default.mariadb11.8", false, false},

		// mysql (aws_db_instance): documented OFF → false (same as postgres ≤14)
		{"mysql 8.0 default → false", "aws_db_instance", "mysql", "8.0", "default.mysql8.0", false, true},
		{"mysql 8.4 default → false", "aws_db_instance", "mysql", "8.4", "default.mysql8.4", false, true},

		// postgres regression boundaries
		{"postgres 15 → true", "aws_db_instance", "postgres", "15.0", "default.postgres15", true, true},
		{"postgres 14 → false", "aws_db_instance", "postgres", "14.0", "default.postgres14", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groupAttr := "parameter_group_name"
			if tc.typ == "aws_rds_cluster" {
				groupAttr = "db_cluster_parameter_group_name"
			}
			db := planResource{
				typ: tc.typ, address: tc.typ + ".db",
				values: map[string]any{
					"engine":         tc.engine,
					"engine_version": tc.version,
					groupAttr:        tc.group,
				},
			}
			got, known := dbTLSEnforced(db, []planResource{db}, configIndex{})
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}
