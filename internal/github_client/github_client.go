package github_client

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt"
	"github.com/google/go-github/github"
	"github.com/kalgurn/github-rate-limits-prometheus-exporter/internal/utils"
	"golang.org/x/oauth2"
)

func GetRemainingLimits(c *github.Client) RateLimits {
	ctx := context.Background()

	limits, _, err := c.RateLimits(ctx)
	if err != nil {
		utils.RespError(err)
	}

	return RateLimits{
		Limit:       limits.Core.Limit,
		Remaining:   limits.Core.Remaining,
		Used:        limits.Core.Limit - limits.Core.Remaining,
		SecondsLeft: time.Until(limits.Core.Reset.Time).Seconds(),
	}
}

func (c TokenConfig) InitClient() *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: c.Token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func (c AppConfig) InitClient() *github.Client {
	if c.InstallationID == 0 && c.OrgName != "" {
		// Retrieve the installation ID if not provided
		auth := TokenConfig{
			Token: generateJWT(c.AppID, c.PrivateKeyPath),
		}
		client := auth.InitClient()

		var err error
		var installation *github.Installation
		ctx := context.Background()
		if c.RepoName != "" {
			installation, _, err = client.Apps.FindRepositoryInstallation(ctx, c.OrgName, c.RepoName)
		} else {
			installation, _, err = client.Apps.FindOrganizationInstallation(ctx, c.OrgName)
		}
		utils.RespError(err)

		c.InstallationID = installation.GetID()
	}

	tr := http.DefaultTransport

	// Wrap the shared transport for use with the app ID 1 authenticating with installation ID 99.
	itr, err := ghinstallation.NewKeyFromFile(tr, c.AppID, c.InstallationID, c.PrivateKeyPath)
	utils.RespError(err)

	// Use installation transport with github.com/google/go-github
	return github.NewClient(&http.Client{Transport: itr})
}

func InitConfig() GithubClient {
	// determine type (app or pat)
	var auth GithubClient
	authType := utils.GetOSVar("GITHUB_AUTH_TYPE")
	if authType == "PAT" {
		auth = TokenConfig{
			Token: utils.GetOSVar("GITHUB_TOKEN"),
		}

	} else if authType == "APP" {
		appID, _ := strconv.ParseInt(utils.GetOSVar("GITHUB_APP_ID"), 10, 64)

		var installationID int64
		envInstallationID := utils.GetOSVar("GITHUB_INSTALLATION_ID")
		if envInstallationID != "" {
			installationID, _ = strconv.ParseInt(envInstallationID, 10, 64)
		}

		auth = AppConfig{
			AppID:          appID,
			InstallationID: installationID,
			OrgName:        utils.GetOSVar("GITHUB_ORG_NAME"),
			RepoName:       utils.GetOSVar("GITHUB_REPO_NAME"),
			PrivateKeyPath: utils.GetOSVar("GITHUB_PRIVATE_KEY_PATH"),
		}
	} else {
		err := fmt.Errorf("invalid auth type")
		utils.RespError(err)
		return nil
	}

	return auth

}

// Helper function to generate JWT for GitHub App
func generateJWT(appID int64, privateKeyPath string) string {
	privateKey, err := os.ReadFile(privateKeyPath)
	utils.RespError(err)

	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	utils.RespError(err)

	now := time.Now()
	claims := jwt.StandardClaims{
		Issuer:    fmt.Sprintf("%d", appID),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute * 10).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(parsedKey)
	utils.RespError(err)

	return signedToken
}
