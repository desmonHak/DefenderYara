
rule Trojan_Win32_SusMpPreference_B{
	meta:
		description = "Trojan:Win32/SusMpPreference.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 } //Add-MpPreference  1
		$a_80_2 = {2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 } //-ExclusionProcess  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}