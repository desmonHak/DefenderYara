
rule Trojan_Win32_Tedy_BJO_MTB{
	meta:
		description = "Trojan:Win32/Tedy.BJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f 1f 40 00 83 7d cc 0f 8d 4d ?? 8a 44 15 9c 0f 47 4d b8 34 3a 88 04 11 42 83 fa 13 72 e6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}