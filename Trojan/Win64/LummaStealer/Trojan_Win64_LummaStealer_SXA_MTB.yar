
rule Trojan_Win64_LummaStealer_SXA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 48 95 88 44 24 27 95 88 5c 24 26 88 54 24 25 88 4c 24 24 83 f8 } //10
		$a_03_1 = {89 d7 f7 e9 c1 fa ?? 69 d2 ?? ?? ?? ?? 89 c8 29 d1 81 c1 ?? ?? ?? ?? 39 cb 0f 8d } //3
		$a_01_2 = {89 c8 c1 e9 1f 01 c1 83 e1 fe 29 c8 40 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=15
 
}