
rule Trojan_Win32_ClickFix_GGR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {7c 00 25 00 7b 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 49 00 4e 00 74 00 5d 00 20 00 24 00 5f 00 } //1 |%{([char][INt] $_
	condition:
		((#a_00_0  & 1)*1) >=1
 
}