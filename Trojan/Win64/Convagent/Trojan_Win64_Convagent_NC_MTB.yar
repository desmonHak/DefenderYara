
rule Trojan_Win64_Convagent_NC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 32 ff 40 88 7c 24 ?? e8 6f ec ff ff 8a d8 8b 0d f3 d4 02 00 83 f9 ?? 0f 84 1d 01 00 00 85 c9 75 4a } //5
		$a_01_1 = {41 32 6d 61 36 41 77 } //1 A2ma6Aw
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_Convagent_NC_MTB_2{
	meta:
		description = "Trojan:Win64/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 57 c0 0f 11 44 24 08 0f 11 44 24 18 48 8d 0d ce 99 02 00 48 89 4c 24 08 48 89 44 24 10 48 8b 44 24 30 48 89 44 24 18 48 8d 44 24 38 48 89 44 24 20 48 8d 44 24 08 48 89 04 24 e8 a2 fa 02 00 31 c0 } //2
		$a_01_1 = {48 8d 05 90 d4 3d 00 48 89 04 24 e8 c7 78 fd ff 48 8b 84 24 80 00 00 00 84 00 8b 8c 24 88 00 00 00 48 63 c9 48 81 f9 00 00 00 40 0f 87 25 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}