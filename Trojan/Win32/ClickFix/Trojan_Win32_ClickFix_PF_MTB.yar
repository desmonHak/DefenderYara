
rule Trojan_Win32_ClickFix_PF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.PF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {2d 00 77 00 20 00 68 00 20 00 2d 00 65 00 70 00 20 00 62 00 20 00 2d 00 63 00 20 00 22 00 69 00 65 00 78 00 20 00 28 00 69 00 77 00 72 00 } //3 -w h -ep b -c "iex (iwr
		$a_00_2 = {2d 00 75 00 73 00 65 00 62 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 -useb).Content
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1) >=5
 
}