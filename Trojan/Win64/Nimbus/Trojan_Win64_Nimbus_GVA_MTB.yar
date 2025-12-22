
rule Trojan_Win64_Nimbus_GVA_MTB{
	meta:
		description = "Trojan:Win64/Nimbus.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 08 d8 44 08 d2 41 30 d0 41 80 f0 ff 41 80 f1 ff b2 ff 80 f2 de 45 08 c8 80 ca de 41 80 f0 ff 41 20 d0 48 63 d0 44 88 04 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}