
rule Trojan_Win64_Tedy_CED_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CED!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 7f 08 48 8d 40 10 49 83 e9 01 75 e2 } //1
		$a_01_1 = {48 8b cb 41 8b c7 be 01 00 00 00 80 31 11 48 03 ce 48 2b c6 75 f5 48 8b c3 49 8b cf 80 30 65 48 03 c6 48 2b ce } //1
		$a_01_2 = {6b eb 10 33 8b eb eb d0 10 03 10 20 eb eb 90 d8 10 eb 70 40 10 e3 10 cb 70 eb 10 a8 0b 8b eb cb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}