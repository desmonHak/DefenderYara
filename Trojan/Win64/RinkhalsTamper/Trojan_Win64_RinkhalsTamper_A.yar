
rule Trojan_Win64_RinkhalsTamper_A{
	meta:
		description = "Trojan:Win64/RinkhalsTamper.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 83 c1 01 0f be d0 41 0f b6 41 ff 44 31 da 44 69 da 93 01 00 01 84 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}