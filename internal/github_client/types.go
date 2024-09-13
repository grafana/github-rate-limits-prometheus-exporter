package github_client

import (
	"net/http"

	"github.com/google/go-github/github"
)

type AppConfig struct {
	AppID          int64
	InstallationID int64
	OrgName        string
	RepoName       string
	PrivateKeyPath string
}

type TokenConfig struct {
	Token string
}

type RateLimits struct {
	Limit       int
	Remaining   int
	Used        int
	SecondsLeft float64
}

type GithubClient interface {
	InitClient(httpClient *http.Client) *github.Client
}
