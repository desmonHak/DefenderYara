
rule Trojan_Win64_Zusy_PBK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {ac 30 d0 48 c1 c2 ?? aa e2 } //2
		$a_03_1 = {ac d0 c8 2c ?? 34 ?? aa e2 } //2
		$a_03_2 = {4c 89 c2 ac c0 c8 ?? 30 d0 aa 48 c1 ca ?? e2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}