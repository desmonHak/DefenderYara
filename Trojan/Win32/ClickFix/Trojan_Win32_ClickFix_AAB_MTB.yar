
rule Trojan_Win32_ClickFix_AAB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 [0-10] 68 00 74 00 74 00 70 00 [0-50] 6d 00 73 00 68 00 74 00 61 00 [0-10] 68 00 74 00 74 00 70 00 } //1
		$a_00_1 = {6d 00 73 00 65 00 64 00 67 00 65 00 77 00 65 00 62 00 76 00 69 00 65 00 77 00 32 00 2e 00 65 00 78 00 65 00 } //-100 msedgewebview2.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-100) >=1
 
}