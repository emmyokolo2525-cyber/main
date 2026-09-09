param(
  [Parameter(Mandatory = $true)]
  [string] $ContractId,

  [Parameter(Mandatory = $true)]
  [string] $Admin,

  [Parameter(Mandatory = $true)]
  [ValidateSet("Tier1", "Tier2", "Tier3", "AllRegistration")]
  [string] $Domain,

  [string] $Network = "testnet"
)

$ErrorActionPreference = "Stop"

$domainValue = switch ($Domain) {
  "Tier1" { 1 }
  "Tier2" { 2 }
  "Tier3" { 4 }
  "AllRegistration" { 7 }
}

stellar contract invoke `
  --id $ContractId `
  --source $Admin `
  --network $Network `
  -- unpause `
  --admin $Admin `
  --domain $domainValue
