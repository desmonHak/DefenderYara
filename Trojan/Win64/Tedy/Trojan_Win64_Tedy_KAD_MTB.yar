
rule Trojan_Win64_Tedy_KAD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 02 48 83 c2 01 43 8d 0c 80 41 8d 0c c8 88 4a ff 4c 39 d2 } //20
		$a_01_1 = {66 0f fc c0 66 0f db ca 66 0f fc c0 66 0f eb c1 0f 11 41 f0 49 39 c8 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}