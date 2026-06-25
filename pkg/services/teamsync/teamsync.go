// fork(team-sync): OSS implementation of external group → team sync.
//
// This package provides the same behaviour as the Grafana Enterprise
// "Team Sync" feature for OAuth providers that populate identity Groups
// (e.g. Google via [auth.google] with the cloud-identity scope):
//
//   - mappings are stored in the `team_group` table (same table Enterprise
//     uses, created by this fork's migration — see
//     pkg/services/sqlstore/migrations/teamsync_mig.go)
//   - a post-auth hook (priority 45, the slot Enterprise occupies between
//     org-role sync (40) and OAuth token sync (60)) diffs the identity's
//     idP groups against team_group mappings and adds/removes the user's
//     team memberships accordingly
//   - memberships created here are flagged external (team_member.external),
//     so manually added members of mapped teams are never touched — same
//     semantics as Enterprise team sync
//
// Upstream touch points are kept to single lines in:
//   - pkg/services/sqlstore/migrations/migrations.go (register migration)
//   - pkg/services/authn/authnimpl/registration.go   (register hook)
//   - pkg/server/wire.go                             (provider)
package teamsync

import (
	"context"
	"errors"
	"path"
	"strconv"
	"strings"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/setting"
)

// HookPriority places the team sync hook between org role sync (40) and
// OAuth token sync (60) — the same slot Grafana Enterprise uses.
const HookPriority = 45

// ErrTeamGroupAlreadyAdded is returned when the (team, group) mapping exists.
var ErrTeamGroupAlreadyAdded = errors.New("group is already added to this team")

// TeamGroup mirrors the Enterprise team_group row shape.
type TeamGroup struct {
	ID      int64  `xorm:"pk autoincr 'id'" json:"-"`
	OrgID   int64  `xorm:"org_id" json:"orgId"`
	TeamID  int64  `xorm:"team_id" json:"teamId"`
	GroupID string `xorm:"group_id" json:"groupId"`
}

// TableName implements xorm's table-name override.
func (TeamGroup) TableName() string { return "team_group" }

type Service struct {
	db       db.DB
	teamSvc  team.Service
	teamPerm accesscontrol.TeamPermissionsService
	log      log.Logger
	tracer   tracing.Tracer

	// Lazy team auto-creation at login. Off unless [team_sync]
	// auto_create_enabled=true. autoCreateFilters is a glob allow-list
	// (path.Match) over group emails; empty + enabled = all groups.
	autoCreateEnabled bool
	autoCreateFilters []string
}

func ProvideService(
	sqlStore db.DB,
	teamService team.Service,
	teamPermissionsService accesscontrol.TeamPermissionsService,
	routeRegister routing.RouteRegister,
	accessControl accesscontrol.AccessControl,
	tracer tracing.Tracer,
	cfg *setting.Cfg,
) *Service {
	logger := log.New("teamsync")
	enabled, filters := parseAutoCreateConfig(cfg, logger)
	s := &Service{
		db:                sqlStore,
		teamSvc:           teamService,
		teamPerm:          teamPermissionsService,
		log:               logger,
		tracer:            tracer,
		autoCreateEnabled: enabled,
		autoCreateFilters: filters,
	}
	s.registerRoutes(routeRegister, accessControl)
	if enabled {
		logger.Info("Team auto-create enabled", "filters", filters)
	}
	return s
}

// parseAutoCreateConfig reads [team_sync] auto_create_enabled (bool) and
// auto_create_group_filters (comma-separated glob list; env overrides
// GF_TEAM_SYNC_AUTO_CREATE_ENABLED / _GROUP_FILTERS). Invalid globs are
// dropped with a warning so a typo can't silently match nothing forever.
func parseAutoCreateConfig(cfg *setting.Cfg, logger log.Logger) (bool, []string) {
	if cfg == nil {
		return false, nil
	}
	sec := cfg.SectionWithEnvOverrides("team_sync")
	enabled := sec.Key("auto_create_enabled").MustBool(false)
	raw := sec.Key("auto_create_group_filters").MustString("")

	var filters []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			logger.Warn("Ignoring invalid team auto-create glob pattern", "pattern", p, "error", err)
			continue
		}
		filters = append(filters, p)
	}
	return enabled, filters
}

// SyncTeamsHook is registered as an authn post-auth hook. It only acts on
// real user logins from clients that set ClientParams.SyncTeams (OAuth, LDAP,
// JWT-with-groups — see pkg/services/authn/clients), never on session
// authentication, so an empty Groups slice on session requests cannot wipe
// memberships. Sync failures are logged and never block the login.
func (s *Service) SyncTeamsHook(ctx context.Context, id *authn.Identity, _ *authn.Request) error {
	if id == nil || !id.ClientParams.SyncTeams {
		return nil
	}
	if !id.IsIdentityType(claims.TypeUser) {
		return nil
	}
	userID, err := id.GetInternalID()
	if err != nil {
		return nil
	}

	ctx, span := s.tracer.Start(ctx, "teamsync.SyncTeamsHook")
	defer span.End()

	orgID := id.GetOrgID()
	logger := s.log.FromContext(ctx)

	// Lazily provision teams for filter-matching idP groups that have no
	// mapping yet, so the first login of a new group's member creates the
	// team + team_group binding. Strictly best-effort: any failure is logged
	// and never returned, so it can never block login (the contract of this hook).
	s.ensureAutoCreatedTeams(ctx, orgID, id.Groups, logger)

	desired, err := s.GetTeamIDsForGroups(ctx, orgID, id.Groups)
	if err != nil {
		logger.Warn("Failed to resolve team mappings, skipping team sync", "user_id", userID, "error", err)
		return nil
	}
	desiredSet := make(map[int64]struct{}, len(desired))
	for _, teamID := range desired {
		desiredSet[teamID] = struct{}{}
	}

	// Only memberships previously created by sync (team_member.external) are
	// considered for removal; manual memberships always survive.
	current, err := s.teamSvc.GetUserTeamMemberships(ctx, orgID, userID, true, true)
	if err != nil {
		logger.Warn("Failed to load current team memberships, skipping team sync", "user_id", userID, "error", err)
		return nil
	}
	currentSet := make(map[int64]struct{}, len(current))
	for _, m := range current {
		currentSet[m.TeamID] = struct{}{}
	}

	acUser := accesscontrol.User{ID: userID, IsExternal: true}

	for teamID := range desiredSet {
		if _, ok := currentSet[teamID]; ok {
			continue
		}
		if _, err := s.teamPerm.SetUserPermission(ctx, orgID, acUser, strconv.FormatInt(teamID, 10), team.PermissionTypeMember.String()); err != nil {
			logger.Warn("Failed to add team membership", "user_id", userID, "team_id", teamID, "error", err)
			continue
		}
		logger.Debug("Added team membership from group sync", "user_id", userID, "team_id", teamID)
	}

	for teamID := range currentSet {
		if _, ok := desiredSet[teamID]; ok {
			continue
		}
		if _, err := s.teamPerm.SetUserPermission(ctx, orgID, acUser, strconv.FormatInt(teamID, 10), ""); err != nil {
			logger.Warn("Failed to remove team membership", "user_id", userID, "team_id", teamID, "error", err)
			continue
		}
		logger.Debug("Removed team membership from group sync", "user_id", userID, "team_id", teamID)
	}

	return nil
}

// GetTeamIDsForGroups returns the team IDs mapped to any of the given
// external group IDs — the login-time consumption query.
func (s *Service) GetTeamIDsForGroups(ctx context.Context, orgID int64, groups []string) ([]int64, error) {
	teamIDs := make([]int64, 0, 4)
	if len(groups) == 0 {
		return teamIDs, nil
	}
	err := s.db.WithDbSession(ctx, func(sess *db.Session) error {
		return sess.Table("team_group").
			Where("org_id = ?", orgID).
			In("group_id", groups).
			Cols("team_id").
			Find(&teamIDs)
	})
	return teamIDs, err
}

// ensureAutoCreatedTeams lazily creates teams + team_group bindings for the
// user's idP groups that match the configured glob allow-list. Best-effort:
// every failure is logged and swallowed so it can never block login.
func (s *Service) ensureAutoCreatedTeams(ctx context.Context, orgID int64, groups []string, logger log.Logger) {
	if !s.autoCreateEnabled || len(groups) == 0 {
		return
	}
	for _, g := range groups {
		if !s.matchesAutoCreate(g) {
			continue
		}
		if err := s.ensureTeamForGroup(ctx, orgID, g); err != nil {
			logger.Warn("Team auto-create from group failed; skipping (login not blocked)", "group", g, "error", err)
		}
	}
}

// matchesAutoCreate reports whether a group is in scope for auto-creation.
// No filters configured means "all groups" (the caller has already checked
// that auto-create is enabled). Glob syntax is stdlib path.Match (*, ?, []).
func (s *Service) matchesAutoCreate(group string) bool {
	if len(s.autoCreateFilters) == 0 {
		return true
	}
	for _, f := range s.autoCreateFilters {
		if ok, err := path.Match(f, group); err == nil && ok {
			return true
		}
	}
	return false
}

// ensureTeamForGroup idempotently guarantees a team exists for the group and is
// bound via team_group. Mirrors the one-shot sync's find-or-create and tolerates
// concurrent first-logins of the same new group (lost create race → re-resolve).
func (s *Service) ensureTeamForGroup(ctx context.Context, orgID int64, group string) error {
	// Fast path: already mapped → nothing to do.
	if mapped, err := s.GetTeamIDsForGroups(ctx, orgID, []string{group}); err == nil && len(mapped) > 0 {
		return nil
	}

	name := teamNameFromGroup(group)

	// The team may already exist (created out-of-band) but be unbound.
	teamID, err := s.findTeamIDByName(ctx, orgID, name)
	if err != nil {
		return err
	}
	if teamID == 0 {
		created, cErr := s.teamSvc.CreateTeam(ctx, &team.CreateTeamCommand{Name: name, Email: group, OrgID: orgID})
		if cErr == nil {
			teamID = created.ID
		} else {
			// Lost a create race, or an untranslated unique-key conflict: re-resolve by name.
			id, fErr := s.findTeamIDByName(ctx, orgID, name)
			if fErr != nil {
				return fErr
			}
			if id == 0 {
				return cErr
			}
			teamID = id
		}
	}

	if err := s.AddTeamGroup(ctx, orgID, teamID, group); err != nil && !errors.Is(err, ErrTeamGroupAlreadyAdded) {
		return err
	}
	return nil
}

// findTeamIDByName returns the team id for an exact (org, name) match, or 0 if none.
func (s *Service) findTeamIDByName(ctx context.Context, orgID int64, name string) (int64, error) {
	var t team.Team
	var found bool
	err := s.db.WithDbSession(ctx, func(sess *db.Session) error {
		ok, e := sess.Table("team").Where("org_id = ? AND name = ?", orgID, name).Get(&t)
		found = ok
		return e
	})
	if err != nil || !found {
		return 0, err
	}
	return t.ID, nil
}

// teamNameFromGroup derives the team name from a group email's local part
// ("screw_3d2.data.monetization@dragonplus.com" → "screw_3d2.data.monetization").
func teamNameFromGroup(group string) string {
	if i := strings.IndexByte(group, '@'); i > 0 {
		return group[:i]
	}
	return group
}

// ListGroupsForTeam returns the external groups mapped to a team.
func (s *Service) ListGroupsForTeam(ctx context.Context, orgID, teamID int64) ([]*TeamGroup, error) {
	groups := make([]*TeamGroup, 0, 4)
	err := s.db.WithDbSession(ctx, func(sess *db.Session) error {
		return sess.Where("org_id = ? AND team_id = ?", orgID, teamID).Find(&groups)
	})
	return groups, err
}

// AddTeamGroup maps an external group to a team.
func (s *Service) AddTeamGroup(ctx context.Context, orgID, teamID int64, groupID string) error {
	return s.db.WithDbSession(ctx, func(sess *db.Session) error {
		exists, err := sess.Where("org_id = ? AND team_id = ? AND group_id = ?", orgID, teamID, groupID).Exist(&TeamGroup{})
		if err != nil {
			return err
		}
		if exists {
			return ErrTeamGroupAlreadyAdded
		}
		_, err = sess.Insert(&TeamGroup{OrgID: orgID, TeamID: teamID, GroupID: groupID})
		return err
	})
}

// RemoveTeamGroup removes a group→team mapping. Returns the number of rows removed.
func (s *Service) RemoveTeamGroup(ctx context.Context, orgID, teamID int64, groupID string) (int64, error) {
	var affected int64
	err := s.db.WithDbSession(ctx, func(sess *db.Session) error {
		res, err := sess.Where("org_id = ? AND team_id = ? AND group_id = ?", orgID, teamID, groupID).Delete(&TeamGroup{})
		affected = res
		return err
	})
	return affected, err
}
