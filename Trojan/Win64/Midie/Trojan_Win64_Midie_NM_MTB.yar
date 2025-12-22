
rule Trojan_Win64_Midie_NM_MTB{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 57 53 61 66 65 2e 70 64 62 } //2 RWSafe.pdb
		$a_01_1 = {47 50 54 20 31 2e 36 } //2 GPT 1.6
		$a_01_2 = {42 61 61 74 } //1 Baat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_Win64_Midie_NM_MTB_2{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 b7 01 40 88 7c 24 20 8a cb e8 bc fd ff ff e8 9b 0b 00 00 48 8b d8 48 83 38 00 } //3
		$a_01_1 = {48 8b c8 e8 0a fd ff ff 84 c0 74 16 48 8b 1b 48 8b cb e8 b7 00 00 00 45 33 c0 41 8d 50 02 33 c9 ff d3 e8 73 0b 00 00 48 8b d8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Midie_NM_MTB_3{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b cb 33 c9 ff 15 ee 35 06 00 48 8b f8 48 85 c0 74 12 48 8b c8 48 89 43 ?? ff 15 e9 35 06 00 83 f8 ff 75 37 } //2
		$a_03_1 = {53 48 83 ec ?? 4c 8b c1 33 d2 48 8b 0d de ce 05 00 ff 15 98 72 02 00 85 c0 75 16 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_Win64_Midie_NM_MTB_4{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 7c 24 ?? 00 49 0f 44 d6 4c 8d 44 24 ?? 4c 8d 7c 24 ?? 4c 89 f9 e8 21 f3 ff ff 4c 8d a4 24 } //2
		$a_03_1 = {48 89 ce 0f b6 81 ?? 00 00 00 88 91 ?? 00 00 00 48 8d 0d 67 01 00 00 48 63 04 81 48 01 c8 ff e0 0f b6 c2 ff c8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}