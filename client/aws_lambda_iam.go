package client

func lambdaS3Flows(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, extra *[]*Element, warnings *[]string) []*Flow {
	var flows []*Flow
	for _, fn := range resources {
		if fn.typ != "aws_lambda_function" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(fn.address)
		roleRefs := idx.attrRefs(fn.address, "role")
		fnEl := byAddr[fn.address]
		if fnEl == nil {
			fnEl = awsLambdaFunctionElement(fn)
		}
		got := bucketFlowsForRole(fnEl, mod, roleRefs, resources, data, idx, elements, warnings)
		if len(got) == 0 {
			continue
		}
		if byAddr[fn.address] == nil {
			*extra = append(*extra, fnEl)
			byAddr[fn.address] = fnEl
		}
		flows = append(flows, got...)
	}
	return flows
}
