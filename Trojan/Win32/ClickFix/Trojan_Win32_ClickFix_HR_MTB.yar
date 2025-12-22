
rule Trojan_Win32_ClickFix_HR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 } //1  msiexec /
		$a_00_1 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 2f 00 } //1 \msiexec.exe /
		$a_00_2 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_3 = {2e 00 6d 00 73 00 69 00 } //-50 .msi
		$a_00_4 = {2e 00 6d 00 73 00 70 00 } //-50 .msp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*-50+(#a_00_4  & 1)*-50) >=11
 
}