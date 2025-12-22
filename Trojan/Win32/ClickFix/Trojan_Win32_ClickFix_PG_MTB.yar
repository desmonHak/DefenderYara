
rule Trojan_Win32_ClickFix_PG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.PG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //2
		$a_00_1 = {3b 00 20 00 6d 00 6b 00 64 00 69 00 72 00 } //1 ; mkdir
		$a_00_2 = {53 00 70 00 6c 00 69 00 74 00 2d 00 50 00 61 00 74 00 68 00 20 00 24 00 } //1 Split-Path $
		$a_00_3 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 20 00 2d 00 6f 00 20 00 24 00 } //1 -UseBasicPar -o $
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}