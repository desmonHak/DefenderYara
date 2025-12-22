
rule Trojan_MacOS_Amos_EV_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 a0 c3 1f b8 a8 c3 5f b8 a9 f0 86 52 08 7d 09 1b e8 0b 00 b9 08 00 00 94 e8 0b 40 b9 09 09 c0 1a 29 7d 00 1b 00 01 09 6b fd 7b 41 a9 ff 83 00 91 } //1
		$a_01_1 = {e8 0f 40 f9 e9 13 40 b9 08 69 e9 38 e9 0f 40 b9 08 01 09 4a e9 93 00 91 29 11 00 91 ea 13 40 b9 28 69 2a 38 e0 0f 40 b9 2d 01 00 94 e0 0f 00 b9 01 00 00 14 e8 13 40 b9 08 05 00 11 e8 13 00 b9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}