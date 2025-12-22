
rule Trojan_Win64_Convagent_LMA_MTB{
	meta:
		description = "Trojan:Win64/Convagent.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 58 00 00 00 00 48 83 fa 0d 72 ?? 48 ba 55 61 39 65 6e 61 62 6c 48 33 10 49 b8 61 62 6c 65 5f 69 66 49 4c 33 40 05 49 09 d0 0f } //20
		$a_01_1 = {48 8b 44 24 48 48 8b 8e d0 02 00 00 48 8b 96 d8 02 00 00 48 29 ca 48 c1 fa 03 48 39 d0 0f 83 77 01 00 00 4c 8b 86 98 02 00 00 4c 3b 86 a0 02 00 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}