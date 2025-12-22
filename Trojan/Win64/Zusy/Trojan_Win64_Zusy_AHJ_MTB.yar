
rule Trojan_Win64_Zusy_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 0f af c2 8b 0c 01 89 4d e4 48 8b 4d b8 b8 05 00 00 00 48 98 ba 08 00 00 00 48 63 d2 48 0f af c2 8b 4c 01 } //20
		$a_01_1 = {48 63 d2 48 0f af c2 0f b7 0c 01 89 8d 4c ff ff ff 8b 8d 4c ff ff ff c1 f9 0c 0f b7 c9 89 8d 48 ff ff ff 8b 8d 4c ff ff ff } //30
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}