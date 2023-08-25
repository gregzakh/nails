<#
 # Retrieving Windiws system calls.
 #>
using namespace System.Runtime.InteropServices

$GetDllExports = {
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$Module)
  end {
    $uint32_sz, $uint16_sz = ([UInt32]0, [UInt16]0).ForEach{[Marshal]::SizeOf($_)}
    ($exp = $ExecutionContext.SessionState.PSVariable.Get("__$Module").Value) ? $exp : $(
      $mod = ($ps = Get-Process -Id $PID).Modules.Where{$_.ModuleName -match "^$Module"}.BaseAddress
      $ps.Dispose() && $($jmp = ($mov = [Marshal]::ReadInt32($mod, 0x3C)) + $uint32_sz)
      $jmp = switch ([BitConverter]::ToUInt16([BitConverter]::GetBytes([Marshal]::ReadInt16($mod, $jmp)), 0)) {
        0x014C {0x20, 0x78, 0x7C} 0x8664 {0x40, 0x88, 0x8C} default { [SystemException]::new() }
      }
      $tmp, $fun = $mod."ToInt$($jmp[0])"(), @{}
      $va, $sz = $jmp[1,2].ForEach{[Marshal]::ReadInt32($mod, $mov + $_)}
      ($ed = @{bs = 0x10; nf = 0x14; nn = 0x18; af = 0x1C; an = 0x20; ao = 0x24}).Keys.ForEach{
        $val = [Marshal]::ReadInt32($mod, $va + $ed.$_)
        Set-Variable -Name $_ -Value ($_.StartsWith('a') ? $tmp + $val : $val) -Scope Script
      }
      function Assert-Forwarder([UInt32]$fa) { end { ($va -le $fa) -and ($fa -lt ($va + $sz)) } }
      (0..($nf - 1)).ForEach{
        $fun[$bs + $_] = (Assert-Forwarder ($fa = [Marshal]::ReadInt32([IntPtr]($af + $_ * $uint32_sz)))) ? @{
          Address = ''; Forward = [Marshal]::PtrToStringAnsi([IntPtr]($tmp + $fa))
        } : @{Address = [IntPtr]($tmp + $fa); Forward = ''}
      }
      Set-Variable -Name "__$Module" -Value ($exp = (0..($nn - 1)).ForEach{
        [PSCustomObject]@{
          Ordinal = ($ord = $bs + [Marshal]::ReadInt16([IntPtr]($ao + $_ * $uint16_sz)))
          Address = $fun[$ord].Address
          Name = [Marshal]::PtrToStringAnsi([IntPtr]($tmp + [Marshal]::ReadInt32([IntPtr]($an + $_ * $uint32_sz))))
          Forward = $fun[$ord].Forward
        }
      }) -Option ReadOnly -Scope Global -Visibility Private
      $exp
    )
  }
}

if ([IntPtr]::Size -ne 8) {
  Write-Warning 'this PoC required x64 Windows.'
  return
}

$GetDllExports.Invoke('ntdll').Where{$_.Name.StartsWith('Nt')}.ForEach{
  # 4c 8b d1         mov  r10, rcx
  # b8 xx xx xx xx   mov  eax, [syscall number]
  # ...
  # 0f 05            syscall
  # c3               retn  ; [Marshal]::ReadByte($_.Address, 20) -eq 0xC3
  if ([Marshal]::ReadInt32($_.Address) -eq  0xB8D18B4C) {
    [PSCustomObject]@{
      Name = $_.Name # SCH is hexadecimal representation of syscall value
      SCH = '{0:X3}' -f ($sc = [Marshal]::ReadInt32($_.Address, 4))
      SysCall = $sc
    }
  }
} | Sort-Object SysCall
