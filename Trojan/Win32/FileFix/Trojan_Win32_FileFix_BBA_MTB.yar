
rule Trojan_Win32_FileFix_BBA_MTB{
	meta:
		description = "Trojan:Win32/FileFix.BBA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 46 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //1 ([System.IO.File]::ReadAllBytes($
		$a_00_1 = {5b 00 72 00 65 00 67 00 65 00 78 00 5d 00 3a 00 3a 00 4d 00 61 00 74 00 63 00 68 00 65 00 73 00 28 00 24 00 } //1 [regex]::Matches($
		$a_00_2 = {2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //1 .GetBytes($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}