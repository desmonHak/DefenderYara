
rule Trojan_Win32_PowExcEnv_PB_MTB{
	meta:
		description = "Trojan:Win32/PowExcEnv.PB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //2 Add-MpPreference
		$a_00_1 = {2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //1 -ExclusionPath
		$a_00_2 = {28 00 47 00 65 00 74 00 2d 00 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 29 00 } //1 (Get-Location)
		$a_00_3 = {2d 00 46 00 6f 00 72 00 63 00 65 00 } //1 -Force
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}