
rule Trojan_Win32_FileFix_HHA_MTB{
	meta:
		description = "Trojan:Win32/FileFix.HHA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 28 00 69 00 72 00 6d 00 20 00 24 00 } //1 iex(irm $
		$a_00_1 = {3b 00 69 00 65 00 78 00 20 00 24 00 } //1 ;iex $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}