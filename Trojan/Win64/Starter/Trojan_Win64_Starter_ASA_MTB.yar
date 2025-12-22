
rule Trojan_Win64_Starter_ASA_MTB{
	meta:
		description = "Trojan:Win64/Starter.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 c2 8b 45 fc 48 98 48 8d 0c ?? ?? ?? ?? ?? 48 8b 45 18 48 01 c8 8b 00 48 98 83 e0 3f 0f b6 44 05 b0 88 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}