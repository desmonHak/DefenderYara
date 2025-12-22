
rule Trojan_Win32_Amadey_ARA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b4 8b 0c 85 38 a8 41 00 8a 04 3b 03 ce 88 44 19 2e 43 3b da 7c e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}