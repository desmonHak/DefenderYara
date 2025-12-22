
rule Trojan_Win64_Cerbu_SX_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 05 00 00 "
		
	strings :
		$a_03_0 = {80 e1 1f 8b c2 80 c1 41 ff c2 88 8c 05 ?? ?? ?? ?? 81 fa ff 01 00 00 73 } //20
		$a_03_1 = {6b db 1f 8d 52 ?? 0f be c1 0f b6 8c 15 e8 ?? ?? ?? ?? d8 84 c9 75 e9 } //10
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e 20 22 25 73 22 20 2f 54 52 20 22 25 73 22 20 2f 46 20 2f 52 4c 20 48 49 47 48 45 53 54 } //5 schtasks /Create /SC ONLOGON /TN "%s" /TR "%s" /F /RL HIGHEST
		$a_01_3 = {63 68 72 6f 6d 65 } //1 chrome
		$a_01_4 = {56 4d 77 61 72 65 } //1 VMware
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=37
 
}