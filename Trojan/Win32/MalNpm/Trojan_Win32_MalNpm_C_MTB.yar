
rule Trojan_Win32_MalNpm_C_MTB{
	meta:
		description = "Trojan:Win32/MalNpm.C!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 65 00 72 00 65 00 20 00 62 00 75 00 6e 00 } //1 where bun
		$a_00_1 = {45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 47 00 65 00 74 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 } //1 Environment]::GetEnvironmentVariable
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}