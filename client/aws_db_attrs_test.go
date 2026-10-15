package client

import "testing"

func TestAWSDBElementStorageEncrypted(t *testing.T) {
	idx := configIndex{}
	// Omitted in Terraform → provider default false is present in the plan.
	el := awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "storage_encrypted": false},
	}, nil, nil, idx, false)
	if el.Attributes["encrypted_at_rest"] != false {
		t.Fatalf("omitted/default false: got %#v want false", el.Attributes["encrypted_at_rest"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "storage_encrypted": true},
	}, nil, nil, idx, false)
	if el.Attributes["encrypted_at_rest"] != true {
		t.Fatalf("true: got %#v", el.Attributes["encrypted_at_rest"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app"},
	}, nil, nil, idx, false)
	if _, ok := el.Attributes["encrypted_at_rest"]; ok {
		t.Fatalf("absent from plan values: got %#v want omitted", el.Attributes["encrypted_at_rest"])
	}
}

func TestAWSDBElementDeletionProtection(t *testing.T) {
	idx := configIndex{}
	el := awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": false},
	}, nil, nil, idx, false)
	if el.Attributes["deletion_protection"] != false {
		t.Fatalf("false: got %#v want false", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": true},
	}, nil, nil, idx, false)
	if el.Attributes["deletion_protection"] != true {
		t.Fatalf("true: got %#v", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app"},
	}, nil, nil, idx, false)
	if _, ok := el.Attributes["deletion_protection"]; ok {
		t.Fatalf("absent from plan values: got %#v want omitted", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": false},
	}, nil, nil, idx, true)
	if el.Attributes["deletion_protection"] != true {
		t.Fatalf("prevent_destroy wins over false: got %#v", el.Attributes["deletion_protection"])
	}
}

func TestAWSDBElementProviderDeletionProtection(t *testing.T) {
	idx := configIndex{}
	for _, typ := range []string{"aws_db_instance", "aws_rds_cluster"} {
		addr := typ + ".a"
		t.Run(typ+"/true", func(t *testing.T) {
			el := awsDBElement(planResource{
				typ: typ, address: addr,
				values: map[string]any{"identifier": "app", "deletion_protection": true},
			}, nil, nil, idx, false)
			if el.Attributes["provider_deletion_protection"] != true {
				t.Fatalf("got %#v", el.Attributes["provider_deletion_protection"])
			}
		})
		t.Run(typ+"/false", func(t *testing.T) {
			el := awsDBElement(planResource{
				typ: typ, address: addr,
				values: map[string]any{"identifier": "app", "deletion_protection": false},
			}, nil, nil, idx, false)
			if el.Attributes["provider_deletion_protection"] != false {
				t.Fatalf("got %#v", el.Attributes["provider_deletion_protection"])
			}
		})
		t.Run(typ+"/unknown", func(t *testing.T) {
			el := awsDBElement(planResource{
				typ: typ, address: addr,
				values:       map[string]any{"identifier": "app"},
				afterUnknown: map[string]any{"deletion_protection": true},
			}, nil, nil, idx, false)
			if _, ok := el.Attributes["provider_deletion_protection"]; ok {
				t.Fatalf("got %#v want omitted", el.Attributes["provider_deletion_protection"])
			}
		})
		t.Run(typ+"/absent", func(t *testing.T) {
			el := awsDBElement(planResource{
				typ: typ, address: addr,
				values: map[string]any{"identifier": "app"},
			}, nil, nil, idx, false)
			if _, ok := el.Attributes["provider_deletion_protection"]; ok {
				t.Fatalf("got %#v want omitted", el.Attributes["provider_deletion_protection"])
			}
		})
		t.Run(typ+"/prevent_destroy_flag_false", func(t *testing.T) {
			el := awsDBElement(planResource{
				typ: typ, address: addr,
				values: map[string]any{"identifier": "app", "deletion_protection": false},
			}, nil, nil, idx, true)
			if el.Attributes["deletion_protection"] != true {
				t.Fatalf("FR-033 deletion_protection: got %#v", el.Attributes["deletion_protection"])
			}
			if el.Attributes["provider_deletion_protection"] != false {
				t.Fatalf("provider_deletion_protection must stay false: got %#v", el.Attributes["provider_deletion_protection"])
			}
		})
	}
}
