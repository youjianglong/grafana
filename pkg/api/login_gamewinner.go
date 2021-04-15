package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/middleware/cookies"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// GameWinnerLoginResponse 登录返回
type GameWinnerLoginResponse struct {
	Code int            `json:"code"`
	Info GameWinnerUser `json:"info"`
}

// GameWinnerUser 用户信息
type GameWinnerUser struct {
	ID            int                     `json:"id"`
	Name          string                  `json:"name"`
	AvailableTime int64                   `json:"availableTime"`
	State         int                     `json:"state"`
	Permissions   []*GameWinnerPermission `json:"permissions"`
}

// GameWinnerPermission 权限信息
type GameWinnerPermission struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	ParentId    int    `json:"parentId"`
	Host        string `json:"host"`
	Uri         string `json:"uri"`
	Description string `json:"description"`
}

func NewHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Second * 5,
	}
}

func (hs *HTTPServer) GameWinnerLogin(c *models.ReqContext) {
	token := c.Query("token")
	c.Logger.Debug("token = " + token)
	homeUrl := setting.AppSubUrl + "/"
	loginInfo := models.LoginInfo{
		AuthModule: "gamewinner",
	}
	sec := setting.Raw.Section("gamewinner")
	checkUrl := sec.Key("login_check_url")
	projectKey := sec.Key("project_key")
	if sec == nil || checkUrl == nil {
		msg := "Grafana未正确配置"
		c.Logger.Error(msg)
		hs.handleOAuthLoginError(c, loginInfo, LoginError{
			HttpStatus:    http.StatusServiceUnavailable,
			PublicMessage: msg,
		})
		return
	}

	req, err := http.NewRequest(http.MethodGet, checkUrl.String(), nil)
	if err != nil {
		c.Logger.Error(err.Error())
		c.Redirect(homeUrl)
		return
	}
	req.Header.Set("token", token)
	client := NewHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		c.Logger.Error(err.Error())
		c.Redirect(homeUrl)
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.Logger.Warn(resp.Status)
		c.Redirect(homeUrl)
		return
	}
	if resp.Body == nil {
		msg := "BPA响应数据无效：响应数据为"
		c.Logger.Error(msg)
		hs.handleOAuthLoginError(c, loginInfo, LoginError{
			HttpStatus:    http.StatusServiceUnavailable,
			PublicMessage: msg,
			Err:           err,
		})
		return
	}
	buf := &bytes.Buffer{}
	_, err = buf.ReadFrom(resp.Body)
	c.Logger.Debug(buf.String())
	result := &GameWinnerLoginResponse{}
	err = json.Unmarshal(buf.Bytes(), result)
	if err != nil {
		msg := "BPA响应数据无效：" + err.Error()
		c.Logger.Error(msg)
		hs.handleOAuthLoginError(c, loginInfo, LoginError{
			HttpStatus:    http.StatusServiceUnavailable,
			PublicMessage: msg,
			Err:           err,
		})
		return
	}
	if result.Code != 0 {
		msg := "登录失败：" + strconv.Itoa(result.Code)
		c.Logger.Error(msg)
		hs.handleOAuthLoginError(c, loginInfo, LoginError{
			HttpStatus:    http.StatusForbidden,
			PublicMessage: msg,
		})
		return
	}

	if result.Info.Permissions == nil {
		msg := "登录失败：读取BPA权限为空"
		c.Logger.Error(msg)
		hs.handleOAuthLoginError(c, loginInfo, LoginError{
			HttpStatus:    http.StatusForbidden,
			PublicMessage: msg,
		})
		return
	}
	id := strconv.Itoa(result.Info.ID)
	extUser := &models.ExternalUserInfo{
		AuthModule: loginInfo.AuthModule,
		AuthId:     fmt.Sprintf("gamewinner_%d", result.Info.ID),
		Name:       result.Info.Name,
		Login:      id,
		Email:      id + "@gamewinner.cn",
		OrgRoles:   map[int64]models.RoleType{},
	}

	var roleType models.RoleType
	var prefix string
	if projectKey != nil {
		prefix = "/" + projectKey.String() + "/grafana/"
	} else {
		prefix = "/grafana/"
	}

	for _, permission := range result.Info.Permissions {
		if permission.Uri == prefix+string(models.ROLE_ADMIN) {
			roleType = models.ROLE_ADMIN
			break
		}
		if permission.Uri == prefix+string(models.ROLE_EDITOR) {
			roleType = models.ROLE_EDITOR
			continue
		}
		if permission.Uri == prefix+string(models.ROLE_VIEWER) {
			if roleType == "" {
				roleType = models.ROLE_VIEWER
			}
			continue
		}
	}

	if roleType == "" {
		c.Logger.Error("禁止访问")
		c.Redirect(homeUrl)
		return
	}

	extUser.OrgRoles[1] = roleType

	// add/update user in grafana
	cmd := &models.UpsertUserCommand{
		ReqContext:    c,
		ExternalUser:  extUser,
		SignupAllowed: true,
	}
	err = bus.Dispatch(cmd)
	if err != nil {
		hs.handleOAuthLoginErrorWithRedirect(c, loginInfo, err)
		return
	}

	// login
	if err = hs.loginUserWithUser(cmd.Result, c); err != nil {
		hs.handleOAuthLoginErrorWithRedirect(c, loginInfo, err)
		return
	}
	loginInfo.HTTPStatus = http.StatusOK
	hs.HooksService.RunLoginHook(&loginInfo, c)
	metrics.MApiLoginOAuth.Inc()

	if redirectTo, err := url.QueryUnescape(c.GetCookie("redirect_to")); err == nil && len(redirectTo) > 0 {
		if err := hs.ValidateRedirectTo(redirectTo); err == nil {
			cookies.DeleteCookie(c.Resp, "redirect_to", hs.CookieOptionsFromCfg)
			c.Redirect(redirectTo)
			return
		}
		log.Debugf("Ignored invalid redirect_to cookie value: %v", redirectTo)
	}

	c.Redirect(homeUrl)
}
