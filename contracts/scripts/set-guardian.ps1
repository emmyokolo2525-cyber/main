param(
  [Parameter(Mandatory = $true)]
  [string] $ContractId,

  [Parameter(Mandatory = $true)]
  [string] $Admin,

  [Parameter(Mandatory = $true)]
  [string] $Guardian,

  [string] $Network = "testnet"
)

$ErrorActionPreference = "Stop"

stellar contract invoke `
  --id $ContractId `
  --source $Admin `
  --network $Network `
  -- set_guardian `
  --admin $Admin `
  --guardian $Guardian
