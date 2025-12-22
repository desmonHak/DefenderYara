
rule Trojan_Win32_PowExcEnv_G_MTB{
	meta:
		description = "Trojan:Win32/PowExcEnv.G!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 Powershell
		$a_00_1 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //1 add-mppreference
		$a_00_2 = {2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 } //1 -exclusionpath
		$a_00_3 = {24 00 65 00 6e 00 76 00 3a 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 } //1 $env:USERPROFILE
		$a_00_4 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 } //1 appdata
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}