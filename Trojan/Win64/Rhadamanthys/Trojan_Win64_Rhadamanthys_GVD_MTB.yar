
rule Trojan_Win64_Rhadamanthys_GVD_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 8b 44 24 08 41 89 c5 45 28 e5 44 32 6c 24 04 41 f6 dd 31 c0 49 39 d7 0f 92 c0 c1 e0 03 8d 04 40 4a 8b b4 08 ?? ?? ?? ?? 4c 01 d6 4c 89 f8 ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}