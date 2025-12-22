
rule Trojan_Win64_Tedy_CE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f 0d ?? ?? ?? ?? f3 0f 6f 01 66 0f ef c8 f3 0f 7f 09 48 8d 49 ?? 49 2b d4 75 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}