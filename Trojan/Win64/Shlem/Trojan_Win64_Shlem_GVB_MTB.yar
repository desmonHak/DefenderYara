
rule Trojan_Win64_Shlem_GVB_MTB{
	meta:
		description = "Trojan:Win64/Shlem.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 ec 48 8b 45 e0 48 01 d0 44 0f b6 00 0f b6 0d dc 75 00 00 8b 55 ec 48 8b 45 e0 48 01 d0 44 89 c2 31 ca 88 10 83 45 ec 01 eb c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}