package github_client

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v65/github"
	"golang.org/x/oauth2"
)

func GetRemainingLimits(c *github.Client, ctx context.Context) (RateLimits, error) {
	limits, _, err := c.RateLimit.Get(ctx)
	if err != nil {
		return RateLimits{}, err
	}

	return RateLimits{
		Limit:       limits.Core.Limit,
		Remaining:   limits.Core.Remaining,
		Used:        limits.Core.Limit - limits.Core.Remaining,
		SecondsLeft: time.Until(limits.Core.Reset.Time).Seconds(),
	}, nil
}

func (c *TokenConfig) InitClient() (*github.Client, error) {
	return initTokenClient(c, http.DefaultClient)
}

func (c *AppConfig) InitClient() (*github.Client, error) {
	return initAppClient(c, http.DefaultClient)
}

func InitConfig() (GithubClient, error) {
	// determine type (PAT, PAT_FROM_FILE, or APP)
	var auth GithubClient
	authType := os.Getenv("GITHUB_AUTH_TYPE")
	switch authType {
	case "PAT":
		auth = &TokenConfig{
			Token: os.Getenv("GITHUB_TOKEN"),
		}

	case "TOKEN_FROM_PATH":
		tokenPath := os.Getenv("GITHUB_TOKEN_PATH")
		if tokenPath == "" {
			return nil, fmt.Errorf("GITHUB_TOKEN_PATH is required when GITHUB_AUTH_TYPE is TOKEN_FROM_PATH")
		}
		auth = &TokenConfig{
			TokenPath: tokenPath,
		}

	case "APP":
		appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GITHUB_APP_ID: %w", err)
		}

		var installationID int64
		envInstallationID := os.Getenv("GITHUB_INSTALLATION_ID")
		if envInstallationID != "" {
			installationID, err = strconv.ParseInt(envInstallationID, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse GITHUB_INSTALLATION_ID: %w", err)
			}
		}

		auth = &AppConfig{
			AppID:          appID,
			InstallationID: installationID,
			OrgName:        os.Getenv("GITHUB_ORG_NAME"),
			RepoName:       os.Getenv("GITHUB_REPO_NAME"),
			PrivateKeyPath: os.Getenv("GITHUB_PRIVATE_KEY_PATH"),
		}

	default:
		return nil, fmt.Errorf("invalid auth type")
	}

	return auth, nil

}

// Helper function to allow testing client initialization with custom http clients
func initTokenClient(c *TokenConfig, httpClient *http.Client) (*github.Client, error) {
	token, err := resolveToken(c)
	if err != nil {
		return nil, err
	}
	if httpClient == http.DefaultClient {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(ctx, ts)
	}
	return github.NewClient(httpClient), nil
}

// resolveToken returns the GitHub token to use. When TokenPath is set the file
// is read on every call, allowing short-lived/rotated tokens to be picked up
// automatically without restarting the process.
func resolveToken(c *TokenConfig) (string, error) {
	if c.TokenPath == "" {
		return c.Token, nil
	}
	data, err := os.ReadFile(c.TokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %q: %w", c.TokenPath, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %q is empty", c.TokenPath)
	}
	return token, nil
}

// Helper function to allow testing client initialization with custom http clients
func initAppClient(c *AppConfig, httpClient *http.Client) (*github.Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("no http-client provided")
	}
	if c.InstallationID == 0 && c.OrgName != "" {
		token, err := generateJWT(c.AppID, c.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}
		// Retrieve the installation ID if not provided
		auth := &TokenConfig{
			Token: token,
		}
		client, err := initTokenClient(auth, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token client: %w", err)
		}

		var installation *github.Installation
		ctx := context.Background()
		if c.RepoName != "" {
			installation, _, err = client.Apps.FindRepositoryInstallation(ctx, c.OrgName, c.RepoName)
		} else {
			installation, _, err = client.Apps.FindOrganizationInstallation(ctx, c.OrgName)
		}
		if err != nil {
			return nil, err
		}
		c.InstallationID = installation.GetID()
	}

	if httpClient == http.DefaultClient {
		tr := http.DefaultTransport
		itr, err := ghinstallation.NewKeyFromFile(tr, c.AppID, c.InstallationID, c.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{Transport: itr}
	} else {
		// Wrap the existing transport
		tr := httpClient.Transport
		if tr == nil {
			tr = http.DefaultTransport
		}
		itr, err := ghinstallation.NewKeyFromFile(tr, c.AppID, c.InstallationID, c.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		httpClient.Transport = itr
	}

	return github.NewClient(httpClient), nil
}

// Helper function to generate JWT for GitHub App
func generateJWT(appID int64, privateKeyPath string) (string, error) {
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", appID),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(parsedKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
