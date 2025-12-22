
rule Trojan_Win64_Rhadamanthys_PGRM_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.PGRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 48 f2 0f 10 84 24 ?? ?? ?? ?? f2 0f 58 05 ?? ?? ?? ?? f2 0f 59 05 ?? ?? ?? ?? f2 0f 2c c0 0f b6 c0 48 8b 4c 24 48 0f b6 09 33 c8 8b c1 48 8b 4c 24 48 88 01 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}