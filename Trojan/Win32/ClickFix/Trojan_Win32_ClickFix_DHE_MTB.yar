
rule Trojan_Win32_ClickFix_DHE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DHE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //10 -UseBasicParsing
		$a_00_2 = {5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //10 [Convert]::FromBase64String(
		$a_00_3 = {5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //10 [Text.Encoding]::UTF8.GetString(
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}