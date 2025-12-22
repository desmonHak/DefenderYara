
rule Trojan_Win64_Tedy_MKE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {f0 08 17 00 3a 00 00 00 68 1c 17 00 b4 } //15
		$a_01_1 = {03 00 56 00 4d 00 50 00 3c 61 73 73 65 6d } //10
		$a_01_2 = {a0 13 00 00 e0 05 00 00 98 13 00 00 04 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}