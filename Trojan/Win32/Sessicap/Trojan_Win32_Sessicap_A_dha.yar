
rule Trojan_Win32_Sessicap_A_dha{
	meta:
		description = "Trojan:Win32/Sessicap.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 63 64 4f 70 65 6e 53 65 73 73 69 6f 6e } //1 pcdOpenSession
		$a_01_1 = {5c 41 64 6f 00 62 65 64 62 2e 64 61 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}