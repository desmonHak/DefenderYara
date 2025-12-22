
rule Trojan_Win64_Stelega_GVC_MTB{
	meta:
		description = "Trojan:Win64/Stelega.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d1 48 8d 44 10 10 48 89 45 e0 8b 45 f0 48 8b 4d e0 30 01 90 8b 45 f4 ff c0 89 45 f4 8b 45 f4 48 8b 4d 10 3b 41 08 0f 9c c0 0f b6 c0 89 45 ec 83 7d ec 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}