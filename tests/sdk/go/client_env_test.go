package sdk_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAzCloudRegisterHelpFlags(t *testing.T) {
	path, err := exec.LookPath("az")
	if err != nil {
		t.Skip("az not on PATH; soft-skip official CLI recipe check")
	}
	out, err := exec.Command(path, "cloud", "register", "--help").CombinedOutput()
	if err != nil {
		t.Skipf("az cloud register --help failed: %v %s", err, out)
	}
	help := string(out)
	for _, flag := range []string{
		"--name",
		"--endpoint-resource-manager",
		"--endpoint-active-directory",
		"--endpoint-microsoft-graph-resource-id",
		"--skip-endpoint-discovery",
	} {
		if !strings.Contains(help, flag) {
			t.Fatalf("az cloud register --help missing %s\n%s", flag, help)
		}
	}
}

func TestAddAzEnvironmentHelpFlags(t *testing.T) {
	path, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not on PATH; soft-skip Az PowerShell recipe check")
	}
	script := `$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) { Write-Output 'SKIP_NO_AZ_ACCOUNTS'; exit 0 }
Import-Module Az.Accounts -ErrorAction Stop
(Get-Command Add-AzEnvironment).Parameters.Keys | ForEach-Object { $_ }
`
	out, err := exec.Command(path, "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		t.Skipf("pwsh Add-AzEnvironment help failed: %v %s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "SKIP_NO_AZ_ACCOUNTS") {
		t.Skip("Az.Accounts module not installed; soft-skip")
	}
	for _, flag := range []string{
		"ResourceManagerEndpoint",
		"ActiveDirectoryEndpoint",
		"MicrosoftGraphUrl",
		"MicrosoftGraphEndpointResourceId",
	} {
		if !strings.Contains(text, flag) {
			t.Fatalf("Add-AzEnvironment missing parameter %s\n%s", flag, text)
		}
	}
}

func TestAddMgEnvironmentHelpFlags(t *testing.T) {
	path, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not on PATH; soft-skip Microsoft Graph PowerShell recipe check")
	}
	script := `$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) { Write-Output 'SKIP_NO_MG'; exit 0 }
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
(Get-Command Add-MgEnvironment).Parameters.Keys | ForEach-Object { $_ }
`
	out, err := exec.Command(path, "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		t.Skipf("pwsh Add-MgEnvironment help failed: %v %s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "SKIP_NO_MG") {
		t.Skip("Microsoft.Graph.Authentication not installed; soft-skip")
	}
	for _, flag := range []string{"AzureADEndpoint", "GraphEndpoint"} {
		if !strings.Contains(text, flag) {
			t.Fatalf("Add-MgEnvironment missing parameter %s\n%s", flag, text)
		}
	}
}
