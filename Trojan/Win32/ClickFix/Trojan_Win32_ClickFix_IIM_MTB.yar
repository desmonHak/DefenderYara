
rule Trojan_Win32_ClickFix_IIM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 49 00 4f 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 52 00 65 00 61 00 64 00 65 00 72 00 28 00 5b 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 } //1 New-Object IO.StreamReader([Net.WebRequest]::Create(
		$a_00_1 = {69 00 65 00 78 00 } //1 iex
		$a_00_2 = {2e 00 52 00 65 00 61 00 64 00 54 00 6f 00 45 00 6e 00 64 00 } //1 .ReadToEnd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}