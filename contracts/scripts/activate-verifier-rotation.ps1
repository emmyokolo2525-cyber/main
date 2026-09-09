param(
  [Parameter(Mandatory = $true)]
  [string] $ContractId,

  [Parameter(Mandatory = $true)]
  [string] $Admin,

  [string] $Network = "testnet"
)

$ErrorActionPreference = "Stop"

stellar contract invoke `
  --id $ContractId `
  --source $Admin `
  --network $Network `
  -- activate_verifier_rotation `
  --admin $Admin
