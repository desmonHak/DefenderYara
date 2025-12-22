
rule Trojan_Win32_ClickFix_IIB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 |powershell
		$a_00_1 = {5b 00 55 00 72 00 69 00 5d 00 3a 00 3a 00 55 00 6e 00 65 00 73 00 63 00 61 00 70 00 65 00 44 00 61 00 74 00 61 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 [Uri]::UnescapeDataString(
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}