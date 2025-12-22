
rule Trojan_Win64_Quasar_AQS_MTB{
	meta:
		description = "Trojan:Win64/Quasar.AQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 11 48 83 c1 01 01 c2 89 d0 c1 e0 07 01 d0 89 c2 c1 ea 06 31 d0 4c 39 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}