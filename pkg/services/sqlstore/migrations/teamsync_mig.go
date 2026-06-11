// fork(team-sync): creates the team_group table used by external group →
// team sync (pkg/services/teamsync). The schema mirrors the Grafana
// Enterprise team_group table so a future move to Enterprise (or to the new
// IAM Team.spec.externalGroups API, which reads the same table through
// legacy.ExternalGroupReconciler) finds compatible data.
//
// Note: OSS migrations do not create this table upstream — it is created by
// Enterprise migrations. If this instance is ever switched to an Enterprise
// build, reconcile this migration with the Enterprise one first.
package migrations

import (
	. "github.com/grafana/grafana/pkg/services/sqlstore/migrator"
)

func addTeamSyncMigrations(mg *Migrator) {
	teamGroupV1 := Table{
		Name: "team_group",
		Columns: []*Column{
			{Name: "id", Type: DB_BigInt, IsPrimaryKey: true, IsAutoIncrement: true},
			{Name: "org_id", Type: DB_BigInt, Nullable: false},
			{Name: "team_id", Type: DB_BigInt, Nullable: false},
			{Name: "group_id", Type: DB_NVarchar, Length: 190, Nullable: false},
		},
		Indices: []*Index{
			{Cols: []string{"org_id", "team_id", "group_id"}, Type: UniqueIndex},
			{Cols: []string{"org_id", "group_id"}},
		},
	}

	mg.AddMigration("create team_group table (fork team-sync)", NewAddTableMigration(teamGroupV1))
	mg.AddMigration("add unique index team_group.org_id_team_id_group_id (fork team-sync)",
		NewAddIndexMigration(teamGroupV1, teamGroupV1.Indices[0]))
	mg.AddMigration("add index team_group.org_id_group_id (fork team-sync)",
		NewAddIndexMigration(teamGroupV1, teamGroupV1.Indices[1]))
}
