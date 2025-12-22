
rule Trojan_Win32_Aenjaris_GVA_MTB{
	meta:
		description = "Trojan:Win32/Aenjaris.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a b0 00 10 40 00 c0 ce df 80 f6 ab 80 ee a4 88 b0 00 10 40 00 40 81 f8 9b 31 02 00 75 e2 61 68 1d f2 40 00 } //2
		$a_01_1 = {0a fc 84 04 fb df f4 a6 87 13 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}