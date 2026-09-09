param(
  [Parameter(Mandatory = $true)]
  [string] $ContractId,

  [Parameter(Mandatory = $true)]
  [string] $Admin,

  [Parameter(Mandatory = $true)]
  [string] $Verifier,

  [Parameter(Mandatory = $true)]
  [uint64] $ActivationLedger,

  [Parameter(Mandatory = $true)]
  [uint64] $OverlapWindow,

  [Parameter(Mandatory = $true)]
  [uint64] $RollbackWindow,

  [string] $Network = "testnet"
)

$ErrorActionPreference = "Stop"

stellar contract invoke `
  --id $ContractId `
  --source $Admin `
  --network $Network `
  -- schedule_verifier_rotation `
  --admin $Admin `
  --verifier $Verifier `
  --activation_ledger $ActivationLedger `
  --overlap_window $OverlapWindow `
  --rollback_window $RollbackWindow
