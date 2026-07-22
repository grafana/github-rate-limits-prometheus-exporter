package github_client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v65/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestPrivateKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA private key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	path := filepath.Join(t.TempDir(), "testkey.pem")
	if err := os.WriteFile(path, privateKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write temp key file: %v", err)
	}

	return path, privateKey
}

func TestGetRemainingLimits(t *testing.T) {
	var (
		limit        = 100
		remaining    = 63
		used         = 37
		seconds_left = 1500
	)
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetRateLimit,
			struct {
				Resources *github.RateLimits
			}{
				Resources: &github.RateLimits{
					Core: &github.Rate{
						Limit:     limit,
						Remaining: remaining,
						Reset:     github.Timestamp{Time: time.Now().Add(time.Second * time.Duration(seconds_left))},
					},
					Search: &github.Rate{},
				},
			},
		),
	)
	c := github.NewClient(mockedHTTPClient)
	limits, err := GetRemainingLimits(c, context.Background())
	require.NoError(t, err)

	assert.Equal(t, limit, limits.Limit, "The limits should be equal")
	assert.Equal(t, remaining, limits.Remaining, "The remaining limits should be equal")
	assert.Equal(t, used, limits.Used, "The used value should be equal")
	assert.Equal(t, seconds_left, int(math.Ceil(limits.SecondsLeft)), "The seconds left value should be equal")

	assert.NotEqual(t, 99, limits.Limit, "The limit should not be equal")
	assert.NotEqual(t, 99, limits.Remaining, "The remaining limits should not be equal")
	assert.NotEqual(t, 18, limits.Used, "The used value should not be equal")
	assert.NotEqual(t, 18, limits.Used, "The seconds left value should not be equal")
}

func TestInitConfigApp(t *testing.T) {
	t.Setenv("GITHUB_AUTH_TYPE", "APP")
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_INSTALLATION_ID", "1")
	t.Setenv("GITHUB_PRIVATE_KEY_PATH", "/home")

	testAuth := &AppConfig{
		AppID:          1,
		InstallationID: 1,
		PrivateKeyPath: "/home",
	}

	appInitConfig, err := InitConfig()
	require.NoError(t, err)
	assert.Equal(t, appInitConfig, testAuth, "should be equal")

}

func TestInitConfigPAT(t *testing.T) {
	t.Setenv("GITHUB_AUTH_TYPE", "PAT")
	t.Setenv("GITHUB_TOKEN", "token_ahsd")

	testAuth := &TokenConfig{
		Token: "token_ahsd",
	}

	patInitConfig, err := InitConfig()
	require.NoError(t, err)
	assert.Equal(t, patInitConfig, testAuth, "should be equal")

}

func TestInitConfigPATFromFile(t *testing.T) {
	t.Setenv("GITHUB_AUTH_TYPE", "TOKEN_FROM_PATH")
	t.Setenv("GITHUB_TOKEN_PATH", "/var/run/secrets/github/token")

	testAuth := &TokenConfig{
		TokenPath: "/var/run/secrets/github/token",
	}

	patInitConfig, err := InitConfig()
	require.NoError(t, err)
	assert.Equal(t, testAuth, patInitConfig, "should be equal")
}

func TestInitConfigPATFromFileMissingPath(t *testing.T) {
	t.Setenv("GITHUB_AUTH_TYPE", "TOKEN_FROM_PATH")
	t.Setenv("GITHUB_TOKEN_PATH", "")

	_, err := InitConfig()
	require.Error(t, err)
	assert.ErrorContains(t, err, "GITHUB_TOKEN_PATH")
}

func TestInitConfigPATIgnoresTokenPath(t *testing.T) {
	// With GITHUB_AUTH_TYPE=PAT, GITHUB_TOKEN_PATH must not be picked up;
	// users must opt in via TOKEN.
	t.Setenv("GITHUB_AUTH_TYPE", "PAT")
	t.Setenv("GITHUB_TOKEN", "static-token")
	t.Setenv("GITHUB_TOKEN_PATH", "/var/run/secrets/github/token")

	testAuth := &TokenConfig{
		Token: "static-token",
	}

	patInitConfig, err := InitConfig()
	require.NoError(t, err)
	assert.Equal(t, testAuth, patInitConfig, "should be equal")
}

func TestResolveToken(t *testing.T) {
	t.Run("returns static token when TokenPath is empty", func(t *testing.T) {
		token, err := resolveToken(&TokenConfig{Token: "static-token"})
		require.NoError(t, err)
		assert.Equal(t, "static-token", token)
	})

	t.Run("reads token from file when TokenPath is set", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("file-token"), 0600))

		token, err := resolveToken(&TokenConfig{TokenPath: path})
		require.NoError(t, err)
		assert.Equal(t, "file-token", token)
	})

	t.Run("TokenPath takes precedence over Token if both are set", func(t *testing.T) {
		// Defensive: InitConfig never populates both fields, but the resolver
		// should still prefer the file when given a TokenConfig with both.
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("file-token"), 0600))

		token, err := resolveToken(&TokenConfig{
			Token:     "static-token",
			TokenPath: path,
		})
		require.NoError(t, err)
		assert.Equal(t, "file-token", token)
	})

	t.Run("trims surrounding whitespace from token file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("  file-token\n"), 0600))

		token, err := resolveToken(&TokenConfig{TokenPath: path})
		require.NoError(t, err)
		assert.Equal(t, "file-token", token)
	})

	t.Run("re-reads file on every call to support rotation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("first-token"), 0600))

		c := &TokenConfig{TokenPath: path}

		token1, err := resolveToken(c)
		require.NoError(t, err)
		assert.Equal(t, "first-token", token1)

		// Simulate the token being rotated on disk
		require.NoError(t, os.WriteFile(path, []byte("second-token"), 0600))

		token2, err := resolveToken(c)
		require.NoError(t, err)
		assert.Equal(t, "second-token", token2)
	})

	t.Run("returns error when token file does not exist", func(t *testing.T) {
		_, err := resolveToken(&TokenConfig{TokenPath: "/nonexistent/token"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to read token file")
	})

	t.Run("returns error when token file is empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("   \n"), 0600))

		_, err := resolveToken(&TokenConfig{TokenPath: path})
		require.Error(t, err)
		assert.ErrorContains(t, err, "is empty")
	})
}

func TestInitTokenClient_WithTokenPath(t *testing.T) {
	t.Run("succeeds with valid token file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("file-token"), 0600))

		c := &TokenConfig{TokenPath: path}
		client, err := initTokenClient(c, http.DefaultClient)
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("fails when token file is missing", func(t *testing.T) {
		c := &TokenConfig{TokenPath: "/nonexistent/token"}
		_, err := initTokenClient(c, http.DefaultClient)
		require.Error(t, err)
	})
}

func TestInitConfigFailure(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "invalid auth type",
			env:     map[string]string{"GITHUB_AUTH_TYPE": "test"},
			wantErr: "invalid auth type",
		},
		{
			name:    "missing auth type",
			env:     map[string]string{"GITHUB_AUTH_TYPE": ""},
			wantErr: "invalid auth type",
		},
		{
			name: "missing GITHUB_APP_ID",
			env: map[string]string{
				"GITHUB_AUTH_TYPE": "APP",
				"GITHUB_APP_ID":    "",
			},
			wantErr: "GITHUB_APP_ID",
		},
		{
			name: "non-numeric GITHUB_APP_ID",
			env: map[string]string{
				"GITHUB_AUTH_TYPE": "APP",
				"GITHUB_APP_ID":    "not-a-number",
			},
			wantErr: "GITHUB_APP_ID",
		},
		{
			name: "non-numeric GITHUB_INSTALLATION_ID",
			env: map[string]string{
				"GITHUB_AUTH_TYPE":        "APP",
				"GITHUB_APP_ID":           "1",
				"GITHUB_INSTALLATION_ID":  "not-a-number",
				"GITHUB_PRIVATE_KEY_PATH": "/home",
			},
			wantErr: "GITHUB_INSTALLATION_ID",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := InitConfig()
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestInitConfigAppWithoutInstallationID(t *testing.T) {
	t.Setenv("GITHUB_INSTALLATION_ID", "")
	t.Setenv("GITHUB_AUTH_TYPE", "APP")
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_ORG_NAME", "org")
	t.Setenv("GITHUB_PRIVATE_KEY_PATH", "/home")

	testAuth := &AppConfig{
		AppID:          1,
		OrgName:        "org",
		PrivateKeyPath: "/home",
	}

	appInitConfig, err := InitConfig()
	require.NoError(t, err)
	assert.Equal(t, testAuth, appInitConfig, "should be equal")
}

func TestAppConfig_InitClient(t *testing.T) {
	testCases := []struct {
		name              string
		orgName           string
		repoName          string
		providedInstallID int64 // InstallationID provided directly in AppConfig
		expectedInstallID int64 // Expected InstallationID after InitClient
		expectedPattern   string
		method            string
	}{
		{
			name:              "WithInstallationID",
			orgName:           "",
			repoName:          "",
			providedInstallID: 654321,
			expectedInstallID: 654321,
			expectedPattern:   "", // No API call expected
			method:            "",
		},
		{
			name:              "WithOrgName",
			orgName:           "testorg",
			repoName:          "",
			providedInstallID: 0, // To be retrieved via API
			expectedInstallID: 654321,
			expectedPattern:   "/orgs/{org}/installation",
			method:            "GET",
		},
		{
			name:              "WithOrgAndRepoName",
			orgName:           "testorg",
			repoName:          "testrepo",
			providedInstallID: 0, // To be retrieved via API
			expectedInstallID: 654321,
			expectedPattern:   "/repos/{owner}/{repo}/installation",
			method:            "GET",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKeyPath, _ := generateTestPrivateKey(t)

			appID := int64(123456)
			var httpClient *http.Client

			if tc.expectedPattern != "" {
				// Create a mock HTTP client to simulate API call
				mockClient := mock.NewMockedHTTPClient(
					mock.WithRequestMatchHandler(
						mock.EndpointPattern{Pattern: tc.expectedPattern, Method: tc.method},
						http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							// Return mock installation data
							installation := &github.Installation{
								ID: github.Int64(tc.expectedInstallID),
							}
							data, _ := json.Marshal(installation)
							w.WriteHeader(http.StatusOK)
							w.Write(data)
						}),
					),
				)
				httpClient = mockClient
			} else {
				httpClient = http.DefaultClient
			}

			// Initialize the AppConfig
			c := &AppConfig{
				AppID:          appID,
				InstallationID: tc.providedInstallID,
				OrgName:        tc.orgName,
				RepoName:       tc.repoName,
				PrivateKeyPath: privateKeyPath,
			}

			client, err := initAppClient(c, httpClient)
			require.NoError(t, err)
			require.NotNil(t, client, "Expected client not to be nil")

			assert.Equal(t, tc.expectedInstallID, c.InstallationID, "Expected InstallationID to be set correctly")
		})
	}
}

func TestInitAppClient_Errors(t *testing.T) {
	t.Run("nil http client", func(t *testing.T) {
		c := &AppConfig{AppID: 1, InstallationID: 1, PrivateKeyPath: "/some/path"}
		_, err := initAppClient(c, nil)
		require.Error(t, err)
	})

	t.Run("bad private key path when fetching installation ID", func(t *testing.T) {
		// generateJWT is called before any API request; it should fail immediately.
		c := &AppConfig{
			AppID:          123456,
			InstallationID: 0,
			OrgName:        "testorg",
			PrivateKeyPath: "/nonexistent/key.pem",
		}
		_, err := initAppClient(c, mock.NewMockedHTTPClient())
		require.Error(t, err)
	})

	t.Run("API error from FindOrganizationInstallation", func(t *testing.T) {
		privateKeyPath, _ := generateTestPrivateKey(t)

		mockClient := mock.NewMockedHTTPClient(
			mock.WithRequestMatchHandler(
				mock.EndpointPattern{Pattern: "/orgs/{org}/installation", Method: "GET"},
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{"message":"Not Found"}`)
				}),
			),
		)
		c := &AppConfig{
			AppID:          123456,
			InstallationID: 0,
			OrgName:        "testorg",
			PrivateKeyPath: privateKeyPath,
		}
		_, err := initAppClient(c, mockClient)
		require.Error(t, err)
	})

	t.Run("API error from FindRepositoryInstallation", func(t *testing.T) {
		privateKeyPath, _ := generateTestPrivateKey(t)

		mockClient := mock.NewMockedHTTPClient(
			mock.WithRequestMatchHandler(
				mock.EndpointPattern{Pattern: "/repos/{owner}/{repo}/installation", Method: "GET"},
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{"message":"Not Found"}`)
				}),
			),
		)
		c := &AppConfig{
			AppID:          123456,
			InstallationID: 0,
			OrgName:        "testorg",
			RepoName:       "testrepo",
			PrivateKeyPath: privateKeyPath,
		}
		_, err := initAppClient(c, mockClient)
		require.Error(t, err)
	})

	t.Run("invalid private key content when initializing ghinstallation transport", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pem")
		require.NoError(t, os.WriteFile(path, []byte("this is not a valid PEM key"), 0600))

		c := &AppConfig{
			AppID:          123456,
			InstallationID: 654321,
			PrivateKeyPath: path,
		}
		_, err := initAppClient(c, http.DefaultClient)
		require.Error(t, err)
	})
}

func TestGenerateJWT_Errors(t *testing.T) {
	t.Run("non-existent key file", func(t *testing.T) {
		_, err := generateJWT(123456, "/nonexistent/key.pem")
		require.Error(t, err)
	})

	t.Run("invalid PEM content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pem")
		require.NoError(t, os.WriteFile(path, []byte("this is not a valid PEM key"), 0600))

		_, err := generateJWT(123456, path)
		require.Error(t, err)
	})
}

func TestGenerateJWT(t *testing.T) {
	privateKeyPath, privateKey := generateTestPrivateKey(t)

	appID := int64(123456)
	token, err := generateJWT(appID, privateKeyPath)
	require.NoError(t, err)
	assert.NotEmpty(t, token, "expected token not to be empty")

	// Verify the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	assert.True(t, parsedToken.Valid, "the token should be valid")

	// Check claims
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		issuer := claims["iss"]
		assert.Equal(t, fmt.Sprintf("%d", appID), issuer, "expected issuer to be equal app id")

		exp := int64(claims["exp"].(float64))
		now := time.Now().Unix()
		assert.LessOrEqual(t, now, exp, "expected token to not be expired")
	} else {
		t.Error("Failed to parse claims")
	}
}
