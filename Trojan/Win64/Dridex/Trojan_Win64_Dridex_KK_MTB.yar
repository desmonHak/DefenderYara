
rule Trojan_Win64_Dridex_KK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 8c 24 98 00 00 00 40 8a 6c 24 6f 81 f1 ?? ?? ?? ?? 89 8c 24 98 00 00 00 40 20 dd 83 c0 ?? 3b 44 24 4c 0f 92 c3 40 20 dd 89 44 24 7c 40 f6 c5 } //20
		$a_03_1 = {42 f3 33 50 7c 25 ?? ?? ?? ?? 87 85 de 4c a9 a5 53 2c ?? 8e 28 e3 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}