
rule Trojan_Win32_FileFix_GGZ_MTB{
	meta:
		description = "Trojan:Win32/FileFix.GGZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 24 00 5f 00 2d 00 62 00 78 00 6f 00 72 00 24 00 } //1 [char]($_-bxor$
		$a_00_1 = {6a 00 6f 00 69 00 6e 00 28 00 24 00 } //1 join($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}