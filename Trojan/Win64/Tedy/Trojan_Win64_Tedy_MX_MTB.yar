
rule Trojan_Win64_Tedy_MX_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 03 3c 20 77 09 84 c0 74 30 40 84 ff 74 1e 3c 22 75 07 40 84 ff 40 0f 94 c7 8b c8 e8 33 4a 00 00 85 c0 74 03 48 ff c3 48 ff c3 } //1
		$a_01_1 = {63 00 6f 00 6e 00 74 00 6f 00 73 00 6f 00 } //1 contoso
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}