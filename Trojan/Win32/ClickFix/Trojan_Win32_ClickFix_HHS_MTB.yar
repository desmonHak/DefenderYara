
rule Trojan_Win32_ClickFix_HHS_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHS!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 52 00 65 00 6d 00 6f 00 74 00 69 00 6e 00 67 00 2e 00 4d 00 65 00 74 00 61 00 64 00 61 00 74 00 61 00 } //1 GetString([System.Runtime.Remoting.Metadata
		$a_00_1 = {2e 00 56 00 61 00 6c 00 75 00 65 00 29 00 7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 .Value)|powershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}