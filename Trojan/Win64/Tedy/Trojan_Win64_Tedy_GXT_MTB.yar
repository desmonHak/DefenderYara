
rule Trojan_Win64_Tedy_GXT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 24 21 33 80 74 24 22 34 80 74 24 23 35 80 74 24 24 36 80 74 24 25 37 80 74 24 26 38 80 74 24 27 39 66 89 4c 24 28 80 f1 3a 80 74 24 29 3b 34 3c c6 44 24 20 36 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}