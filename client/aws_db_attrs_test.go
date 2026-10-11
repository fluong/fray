package client

import "testing"

func TestAWSDBElementStorageEncrypted(t *testing.T) {
	// Omitted in Terraform → provider default false is present in the plan.
	el := awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "storage_encrypted": false},
	}, false)
	if el.Attributes["encrypted_at_rest"] != false {
		t.Fatalf("omitted/default false: got %#v want false", el.Attributes["encrypted_at_rest"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "storage_encrypted": true},
	}, false)
	if el.Attributes["encrypted_at_rest"] != true {
		t.Fatalf("true: got %#v", el.Attributes["encrypted_at_rest"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app"},
	}, false)
	if _, ok := el.Attributes["encrypted_at_rest"]; ok {
		t.Fatalf("absent from plan values: got %#v want omitted", el.Attributes["encrypted_at_rest"])
	}
}

func TestAWSDBElementDeletionProtection(t *testing.T) {
	el := awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": false},
	}, false)
	if el.Attributes["deletion_protection"] != false {
		t.Fatalf("false: got %#v want false", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": true},
	}, false)
	if el.Attributes["deletion_protection"] != true {
		t.Fatalf("true: got %#v", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app"},
	}, false)
	if _, ok := el.Attributes["deletion_protection"]; ok {
		t.Fatalf("absent from plan values: got %#v want omitted", el.Attributes["deletion_protection"])
	}

	el = awsDBElement(planResource{
		typ: "aws_db_instance", address: "aws_db_instance.a",
		values: map[string]any{"identifier": "app", "deletion_protection": false},
	}, true)
	if el.Attributes["deletion_protection"] != true {
		t.Fatalf("prevent_destroy wins over false: got %#v", el.Attributes["deletion_protection"])
	}
}
