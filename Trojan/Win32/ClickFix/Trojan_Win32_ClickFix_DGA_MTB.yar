
rule Trojan_Win32_ClickFix_DGA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {3d 00 69 00 77 00 72 00 20 00 24 00 } //10 =iwr $
		$a_00_2 = {3b 00 20 00 69 00 65 00 78 00 20 00 24 00 } //10 ; iex $
		$a_00_3 = {20 00 23 00 20 00 } //10  # 
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}