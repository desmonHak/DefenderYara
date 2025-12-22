
rule Trojan_Win32_NSteal_SB{
	meta:
		description = "Trojan:Win32/NSteal.SB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-ff] 73 00 74 00 61 00 72 00 74 00 [0-30] 2f 00 6d 00 69 00 6e 00 } //1
		$a_02_1 = {5c 00 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 [0-ff] 68 00 65 00 6c 00 70 00 65 00 72 00 2e 00 6a 00 73 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}