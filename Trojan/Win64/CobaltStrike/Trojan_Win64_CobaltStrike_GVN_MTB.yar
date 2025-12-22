
rule Trojan_Win64_CobaltStrike_GVN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 e5 48 83 ec 20 b9 e8 03 00 00 48 8b 05 b2 9c 06 00 ff d0 } //2
		$a_01_1 = {48 8b 05 ec 9b 06 00 ff d0 48 89 45 f8 b9 fa 00 00 00 48 8b 05 22 9c 06 00 ff d0 b9 fa 00 00 00 48 8b 05 14 9c 06 00 ff d0 eb 07 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}