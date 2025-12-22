
rule Trojan_Win32_Zusy_ATR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 3b 12 01 72 68 0e 01 a2 8d ef 00 20 9a ef 00 } //4
		$a_01_1 = {b8 69 12 01 00 00 00 00 a2 be 0b 01 } //3
		$a_01_2 = {ca 86 97 00 00 d0 47 00 } //2
		$a_01_3 = {f1 28 04 00 00 80 a0 01 00 30 04 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}