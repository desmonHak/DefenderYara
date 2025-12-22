
rule Trojan_Win64_Rozena_SX_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 4f d1 43 8d 0c 01 0f af c1 0f be d2 69 d2 ?? ?? ?? ?? 48 63 ca 48 69 c9 } //20
		$a_03_1 = {0f 4f d0 45 8d 04 09 48 83 c1 ?? 41 0f af c0 0f be d2 69 d2 ?? ?? ?? ?? 4c 63 c2 c1 fa 1f 4d 69 c0 } //20
		$a_03_2 = {45 8d 50 fc 41 8d 40 e0 41 80 f8 ?? 41 0f 4d c2 66 98 66 42 89 44 4a fe 49 8d 41 01 44 0f b6 44 01 ff 45 84 c0 75 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20+(#a_03_2  & 1)*10) >=30
 
}