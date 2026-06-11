// fork(team-sync): Enterprise-compatible HTTP API for team external groups.
//
// Endpoint shapes follow the Grafana Enterprise Team Sync HTTP API so that
// existing automation (and a potential future move to Enterprise) keeps
// working unchanged:
//
//	GET    /api/teams/:teamId/groups            → [{orgId, teamId, groupId}]
//	POST   /api/teams/:teamId/groups {groupId}  → 200
//	DELETE /api/teams/:teamId/groups?groupId=x  → 200
//	DELETE /api/teams/:teamId/groups/:groupId   → 200 (legacy shape)
//
// Routes are self-registered here so no upstream route table is touched.
package teamsync

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/web"
)

type setTeamGroupCommand struct {
	GroupID string `json:"groupId" binding:"Required"`
}

func (s *Service) registerRoutes(routeRegister routing.RouteRegister, ac accesscontrol.AccessControl) {
	authorize := accesscontrol.Middleware(ac)
	teamResolver := team.MiddlewareTeamUIDResolver(s.teamSvc, ":teamId")

	routeRegister.Group("/api/teams", func(r routing.RouteRegister) {
		r.Get("/:teamId/groups", teamResolver,
			authorize(accesscontrol.EvalPermission(accesscontrol.ActionTeamsRead, accesscontrol.ScopeTeamsID)),
			routing.Wrap(s.getTeamGroupsHandler))
		r.Post("/:teamId/groups", teamResolver,
			authorize(accesscontrol.EvalPermission(accesscontrol.ActionTeamsWrite, accesscontrol.ScopeTeamsID)),
			routing.Wrap(s.addTeamGroupHandler))
		r.Delete("/:teamId/groups", teamResolver,
			authorize(accesscontrol.EvalPermission(accesscontrol.ActionTeamsWrite, accesscontrol.ScopeTeamsID)),
			routing.Wrap(s.removeTeamGroupHandler))
		r.Delete("/:teamId/groups/:groupId", teamResolver,
			authorize(accesscontrol.EvalPermission(accesscontrol.ActionTeamsWrite, accesscontrol.ScopeTeamsID)),
			routing.Wrap(s.removeTeamGroupHandler))
	})
}

func (s *Service) teamIDFromRequest(c *contextmodel.ReqContext) (int64, error) {
	return strconv.ParseInt(web.Params(c.Req)[":teamId"], 10, 64)
}

func (s *Service) getTeamGroupsHandler(c *contextmodel.ReqContext) response.Response {
	teamID, err := s.teamIDFromRequest(c)
	if err != nil {
		return response.Error(http.StatusBadRequest, "teamId is invalid", err)
	}
	groups, err := s.ListGroupsForTeam(c.Req.Context(), c.SignedInUser.GetOrgID(), teamID)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to get team groups", err)
	}
	return response.JSON(http.StatusOK, groups)
}

func (s *Service) addTeamGroupHandler(c *contextmodel.ReqContext) response.Response {
	cmd := setTeamGroupCommand{}
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "bad request data", err)
	}
	teamID, err := s.teamIDFromRequest(c)
	if err != nil {
		return response.Error(http.StatusBadRequest, "teamId is invalid", err)
	}
	if cmd.GroupID == "" {
		return response.Error(http.StatusBadRequest, "groupId is required", nil)
	}

	err = s.AddTeamGroup(c.Req.Context(), c.SignedInUser.GetOrgID(), teamID, cmd.GroupID)
	if errors.Is(err, ErrTeamGroupAlreadyAdded) {
		return response.Error(http.StatusConflict, "Group is already added to this team", err)
	}
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to add group to team", err)
	}
	return response.Success("Group added to Team")
}

func (s *Service) removeTeamGroupHandler(c *contextmodel.ReqContext) response.Response {
	teamID, err := s.teamIDFromRequest(c)
	if err != nil {
		return response.Error(http.StatusBadRequest, "teamId is invalid", err)
	}
	// Enterprise accepts the group either as a query parameter (current shape,
	// supports group IDs containing slashes) or as a path segment (legacy).
	groupID := c.Query("groupId")
	if groupID == "" {
		groupID = web.Params(c.Req)[":groupId"]
	}
	if groupID == "" {
		return response.Error(http.StatusBadRequest, "groupId is required", nil)
	}

	affected, err := s.RemoveTeamGroup(c.Req.Context(), c.SignedInUser.GetOrgID(), teamID, groupID)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to remove group from team", err)
	}
	if affected == 0 {
		return response.Error(http.StatusNotFound, "Group not found", nil)
	}
	return response.Success("Team group removed")
}
