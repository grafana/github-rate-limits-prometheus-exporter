package github_client

import (
	"github.com/google/go-github/v65/github"
)

type AppConfig struct {
	AppID          int64
	InstallationID int64
	OrgName        string
	RepoName       string
	PrivateKeyPath string
}

type TokenConfig struct {
	// Token is a static GitHub token used when TokenPath is empty.
	Token string
	// TokenPath, when set, takes precedence over Token. The token is read
	// from this file on every client initialization, which makes it suitable
	// for short-lived/rotated tokens (e.g. projected service account tokens
	// in Kubernetes or tokens rotated by external secret operators).
	TokenPath string
}

type RateLimits struct {
	Limit       int
	Remaining   int
	Used        int
	SecondsLeft float64
}

type GithubClient interface {
	InitClient() (*github.Client, error)
}
