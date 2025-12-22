
rule Trojan_MacOS_AmosStealz_A_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 } //1 whoami
		$a_00_1 = {2f 00 74 00 6d 00 70 00 2f 00 2e 00 70 00 61 00 73 00 73 00 } //1 /tmp/.pass
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}