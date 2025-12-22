
rule Trojan_MacOS_Amos_DX_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DX!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 03 00 aa e8 7f c0 39 a8 00 f8 36 e0 07 40 f9 47 01 00 94 02 00 00 14 } //1
		$a_01_1 = {88 f2 7d 92 08 21 00 91 89 0a 40 b2 3f 5d 00 f1 08 01 89 9a 17 05 00 91 e0 03 17 aa 2b 01 00 94 f6 03 00 aa e8 02 41 b2 74 a2 00 a9 60 02 00 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}