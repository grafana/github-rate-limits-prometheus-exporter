[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=kalgurn_github-rate-limits-prometheus-exporter&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=kalgurn_github-rate-limits-prometheus-exporter)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=kalgurn_github-rate-limits-prometheus-exporter&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=kalgurn_github-rate-limits-prometheus-exporter)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=kalgurn_github-rate-limits-prometheus-exporter&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=kalgurn_github-rate-limits-prometheus-exporter)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/github-rate-limit-prometheus-exporter)](https://artifacthub.io/packages/search?repo=github-rate-limit-prometheus-exporter)
# Github Rate Limit Prometheus Exporter

A [prometheus](https://prometheus.io/) exporter which scrapes GitHub API for the rate limits used by PAT/GitHub App.

Helm Chart with values and deployment can be found [here](./helm/github-rate-limits-prometheus-exporter)

For the exporter to run you need to supply either a GitHub Token or a set of a GitHub App credentials, alongside with a type of authentication to use (`PAT`, `TOKEN`, or `APP`).

`TOKEN` reads the token from a file on every scrape, which makes it
suitable for short-lived/rotated tokens — e.g. tokens written by an external
secrets operator, refreshed by a sidecar, or a projected Kubernetes service
account token used to exchange for a GitHub token.

### The metrics can then be represented on a [grafana](https://grafana.com) dashboard


![Grafana panel example](./images/example_panel.png)



## Docker

PAT
```sh
docker run -d \
    -e GITHUB_AUTH_TYPE=PAT \
    -e GITHUB_ACCOUNT_NAME=name_of_my_app \
    -e GITHUB_TOKEN=my_token \
    -p 2112:2112 \
    ghcr.io/kalgurn/grl-exporter:latest
```

TOKEN from file (the token is re-read from disk on every scrape, so rotated/short-lived tokens are picked up automatically)
```sh
docker run -d \
    -e GITHUB_AUTH_TYPE=TOKEN_FROM_PATH \
    -e GITHUB_ACCOUNT_NAME=name_of_my_app \
    -e GITHUB_TOKEN_PATH=/var/run/secrets/github/token \
    -v $PWD/path_to/token:/var/run/secrets/github/token:ro \
    -p 2112:2112 \
    ghcr.io/kalgurn/grl-exporter:latest
```

GitHub APP
```sh
docker run -d \
    -e GITHUB_AUTH_TYPE=APP \
    -e GITHUB_APP_ID=my_app_id \
    -e GITHUB_INSTALLATION_ID=my_app_installation_id \
    -e GITHUB_ACCOUNT_NAME=name_of_my_app \
    -e GITHUB_PRIVATE_KEY_PATH=/tmp \
    -v $PWD/path_to/key.pem:/tmp/key.pem \
    -p 2112:2112 \
    ghcr.io/kalgurn/grl-exporter:latest
```

## Environment variables

| Variable                  | Required for                       | Description                                                                                          |
|---------------------------|------------------------------------|------------------------------------------------------------------------------------------------------|
| `GITHUB_AUTH_TYPE`        | all                                | One of `PAT`, `TOKEN_FROM_PATH`, `APP`.                                                                |
| `GITHUB_ACCOUNT_NAME`     | all                                | Value used as the `account` Prometheus label.                                                        |
| `GITHUB_TOKEN`            | `PAT`                              | The GitHub Personal Access Token.                                                                    |
| `GITHUB_TOKEN_PATH`       | `TOKEN`                    | Path to a file containing the GitHub token. Read on every scrape to support rotation.                |
| `GITHUB_APP_ID`           | `APP`                              | GitHub App ID.                                                                                       |
| `GITHUB_INSTALLATION_ID`  | `APP` (optional)                   | Installation ID. If omitted, it is discovered via `GITHUB_ORG_NAME` (and optional `GITHUB_REPO_NAME`).|
| `GITHUB_ORG_NAME`         | `APP` (when no `INSTALLATION_ID`)  | Organization to look up the installation for.                                                        |
| `GITHUB_REPO_NAME`        | `APP` (optional)                   | Repository name to scope the installation lookup.                                                    |
| `GITHUB_PRIVATE_KEY_PATH` | `APP`                              | Path to the GitHub App private key (PEM).                                                            |
