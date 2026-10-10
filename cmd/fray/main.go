package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	var opt options
	var setupCheck bool
	flag.StringVar(&opt.Plan, "plan", "", "path to terraform show -json output")
	flag.StringVar(&opt.Source, "source", "", "Terraform root module, read for lifecycle and block locations")
	flag.StringVar(&opt.Config, "config", "", "path to fray.yaml")
	flag.StringVar(&opt.Waivers, "waivers", "", "path to .fray/waivers.yml (missing file = no waivers)")
	flag.StringVar(&opt.Mitigations, "mitigations", "", "deprecated: path to mitigations.yaml (non-empty entries fail with a migration message)")
	flag.StringVar(&opt.BaseCommit, "base-commit", "", "PR base commit sha (remote baseline lookup)")
	flag.StringVar(&opt.BaseSource, "base-source", "", "Terraform root at the PR base commit (module-arg compare)")
	flag.StringVar(&opt.Out, "out", ".", "directory for findings.json, findings.sarif, threat-model.md, and pr-comment.md")
	flag.StringVar(&opt.Repo, "repo", "", "source.repo recorded on the DFD (hashed when redaction is on)")
	flag.StringVar(&opt.Commit, "commit", "", "source.commit recorded on the DFD")
	flag.StringVar(&opt.Declared, "declared-source", "", "path recorded on declared elements; defaults to -config")
	flag.StringVar(&opt.Branch, "branch", "", "git branch of this commit (local only; used to set is_default_branch)")
	flag.StringVar(&opt.DefaultBranch, "default-branch", "", "repository default branch (local only; required)")
	flag.StringVar(&opt.Remote, "remote", "", "Fray API base URL")
	flag.StringVar(&opt.APIKey, "api-key", "", "org API key; defaults to FRAY_API_KEY")
	flag.StringVar(&opt.OIDCToken, "oidc-token", "", "GitHub Actions OIDC token; defaults to FRAY_OIDC_TOKEN")
	flag.StringVar(&opt.PayloadOut, "payload-out", "", "write the exact POST body to this path")
	flag.BoolVar(&opt.DryRun, "dry-run", false, "build the scan payload but do not POST")
	flag.BoolVar(&opt.ShowPayload, "show-payload", false, "print the exact JSON that would be sent")
	flag.BoolVar(&opt.FailOnUnenrolled, "fail-on-unenrolled", false, "exit non-zero when the GitHub App install does not cover this repo")
	flag.BoolVar(&opt.ExternalPlan, "external-plan", false, "plan came from Action plan-file (validate JSON, warn on source mismatch; empty-DFD refuse applies to all plans)")
	flag.BoolVar(&setupCheck, "check", false, "run setup checks only (no plan scan, no API)")
	flag.Parse()

	if setupCheck {
		if opt.Source == "" || opt.Config == "" || opt.Remote == "" {
			fmt.Fprintln(os.Stderr, "usage: fray -check -source infra -config fray.yaml -remote url [-plan plan.json -external-plan] [-waivers .fray/waivers.yml]")
			os.Exit(2)
		}
		os.Exit(runSetupCheck(opt))
	}

	if opt.Plan == "" || opt.Source == "" || opt.Config == "" || opt.Remote == "" {
		fmt.Fprintln(os.Stderr, "usage: fray -plan plan.json -source infra -config fray.yaml -remote url -default-branch main [-waivers .fray/waivers.yml] [-out dir]")
		os.Exit(2)
	}
	if opt.Declared == "" {
		opt.Declared = opt.Config
	}

	fail, err := runRemote(opt)
	if err != nil {
		if errors.Is(err, errEnrollmentRejected) {
			// Annotation + summary already emitted.
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if fail {
		os.Exit(1)
	}
}
