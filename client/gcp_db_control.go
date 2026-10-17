package client

// attachCloudSQLControlPlane sets FR-046 control-plane classes when the workload
// SA has roles/cloudsql.admin (FR-046.md; data-plane roles stay FR-028 only).
func attachCloudSQLControlPlane(flow *Flow, sa string, sqlRes planResource, projectIAM []planResource, idx configIndex) {
	if sa == "" {
		return
	}
	cause := cloudSQLAdminBinding(sa, projectIAM, idx)
	if cause == "" {
		return
	}
	flow.AuthzDBControlClasses = allDBControlClasses()
	flow.AuthzDBControlScope = "account"
	if flow.Causes == nil {
		flow.Causes = map[string]string{}
	}
	flow.Causes["authz_db_control_classes"] = cause
}

func cloudSQLAdminBinding(sa string, projectIAM []planResource, idx configIndex) string {
	for _, m := range expandProjectIAM(projectIAM) {
		role, _ := m.values["role"].(string)
		if role != "roles/cloudsql.admin" {
			continue
		}
		if !projectIAMMemberMatches(m, sa) {
			continue
		}
		if iamConditionBlockPresent(m, idx) {
			continue
		}
		return m.address
	}
	return ""
}
