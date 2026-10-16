package client

import "testing"

func TestResolveSingleByRef(t *testing.T) {
	lc := planResource{address: "module.app.aws_launch_configuration.this", typ: "aws_launch_configuration"}
	lcOther := planResource{address: "module.app.aws_launch_configuration.other", typ: "aws_launch_configuration"}
	resources := []planResource{lc, lcOther}
	data := []planResource{
		{address: "data.aws_launch_configuration.d", typ: "aws_launch_configuration"},
	}

	asgOpts := resolveSingleByRefOpts{
		ResourceType:      "aws_launch_configuration",
		SkipVarRef:        true,
		BareModule:        bareModuleSkipWithVar,
		EmptyNameData:     emptyNameContinue,
		EmptyNameManaged:  emptyNameContinue,
		ModuleOutputDepth: 0,
	}
	subnetOpts := resolveSingleByRefOpts{
		ResourceType:      "aws_subnet",
		SkipVarRef:        true,
		BareModule:        bareModuleSkipAfterModuleOutput,
		EmptyNameData:     emptyNameFail,
		EmptyNameManaged:  emptyNameFail,
		ModuleOutputDepth: 0,
	}

	tests := []struct {
		name    string
		opts    resolveSingleByRefOpts
		refs    []string
		wantOK  bool
		wantAdr string
	}{
		{
			name:    "managed hit ASG opts",
			opts:    asgOpts,
			refs:    []string{"aws_launch_configuration.this"},
			wantOK:  true,
			wantAdr: lc.address,
		},
		{
			name:    "skip var ASG opts",
			opts:    asgOpts,
			refs:    []string{"var.lc", "aws_launch_configuration.this"},
			wantOK:  true,
			wantAdr: lc.address,
		},
		{
			name:    "skip bare module before data ASG opts",
			opts:    asgOpts,
			refs:    []string{"module.foo", "aws_launch_configuration.this"},
			wantOK:  true,
			wantAdr: lc.address,
		},
		{
			name:   "empty name managed continue ASG opts",
			opts:   asgOpts,
			refs:   []string{"aws_launch_configuration."},
			wantOK: false,
		},
		{
			name:   "ambiguous two managed ASG opts",
			opts:   asgOpts,
			refs:   []string{"aws_launch_configuration.this", "aws_launch_configuration.other"},
			wantOK: false,
		},
		{
			name:    "data hit ASG opts",
			opts:    asgOpts,
			refs:    []string{"data.aws_launch_configuration.d"},
			wantOK:  true,
			wantAdr: "data.aws_launch_configuration.d",
		},
		{
			name:   "empty name data fail subnet opts",
			opts:   subnetOpts,
			refs:   []string{"data.aws_subnet."},
			wantOK: false,
		},
		{
			name:   "empty name managed fail subnet opts",
			opts:   subnetOpts,
			refs:   []string{"aws_subnet."},
			wantOK: false,
		},
		{
			name:   "bare module after module output skipped subnet opts",
			opts:   subnetOpts,
			refs:   []string{"module.subnet", "aws_subnet.missing"},
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveSingleByRef(tc.refs, resources, data, configIndex{}, tc.opts)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if tc.wantOK && got.address != tc.wantAdr {
				t.Fatalf("address=%q want %q", got.address, tc.wantAdr)
			}
		})
	}
}

func TestResolveUniqueSecurityGroupPeerAddress(t *testing.T) {
	idx := configIndex{}
	ruleMod := "module.vpc"
	tests := []struct {
		name    string
		refs    []string
		wantOK  bool
		wantUnk bool
		wantAdr string
	}{
		{
			name:    "single managed",
			refs:    []string{"aws_security_group.peer"},
			wantOK:  true,
			wantAdr: "module.vpc.aws_security_group.peer",
		},
		{
			name:    "empty name skipped then unk",
			refs:    []string{"aws_security_group."},
			wantUnk: true,
		},
		{
			name:    "two peers unk",
			refs:    []string{"aws_security_group.a", "aws_security_group.b"},
			wantUnk: true,
		},
		{
			name:    "indirect unk",
			refs:    []string{"var.peer_sg"},
			wantUnk: true,
		},
		{
			name:    "skip bare module",
			refs:    []string{"module.foo", "aws_security_group.peer"},
			wantOK:  true,
			wantAdr: "module.vpc.aws_security_group.peer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok, unk := resolveUniqueSecurityGroupPeerAddress(tc.refs, ruleMod, idx)
			if ok != tc.wantOK || unk != tc.wantUnk {
				t.Fatalf("ok=%v unk=%v want ok=%v unk=%v", ok, unk, tc.wantOK, tc.wantUnk)
			}
			if tc.wantOK && addr != tc.wantAdr {
				t.Fatalf("addr=%q want %q", addr, tc.wantAdr)
			}
		})
	}
}
