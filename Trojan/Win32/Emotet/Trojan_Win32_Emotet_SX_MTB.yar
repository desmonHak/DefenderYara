
rule Trojan_Win32_Emotet_SX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 30 40 3b c7 7c e7 } //3
		$a_01_1 = {c6 05 b0 1a 01 03 4c c6 05 b1 1a 01 03 6f c6 05 b2 1a 01 03 63 c6 05 b3 1a 01 03 61 c6 05 b4 1a 01 03 6c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}