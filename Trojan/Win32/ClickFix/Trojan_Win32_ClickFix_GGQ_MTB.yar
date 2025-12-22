
rule Trojan_Win32_ClickFix_GGQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {7c 00 25 00 7b 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 49 00 4e 00 74 00 5d 00 20 00 24 00 5f 00 } //1 |%{([char][INt] $_
		$a_00_1 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 6a 00 6f 00 69 00 6e 00 28 00 27 00 } //1 [string]::join('
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}