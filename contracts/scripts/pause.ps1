param(
  [Parameter(Mandatory = $true)]
  [string] $ContractId,

  [Parameter(Mandatory = $true)]
  [string] $Caller,

  [Parameter(Mandatory = $true)]
  [ValidateSet("Tier1", "Tier2", "Tier3", "AllRegistration")]
  [string] $Domain,

  [Parameter(Mandatory = $true)]
  [uint64] $DurationSecs,

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
  --source $Caller `
  --network $Network `
  -- pause `
  --caller $Caller `
  --domain $domainValue `
  --duration_secs $DurationSecs
