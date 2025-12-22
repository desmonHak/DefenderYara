
rule Trojan_Win32_ClickFix_HHQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 77 00 69 00 6e 00 20 00 6d 00 69 00 6e 00 69 00 20 00 2d 00 65 00 } //1 =powershell -win mini -e
		$a_00_1 = {29 00 3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 77 00 20 00 68 00 20 00 2d 00 65 00 70 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 66 00 20 00 24 00 } //1 );powershell -w h -ep bypass -f $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}