
rule Trojan_Win32_Stealer_MK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 d9 89 c2 d3 e2 88 d9 8b 74 24 10 0f a5 c6 31 c0 f6 c3 20 0f 45 f2 0f 45 d0 } //15
		$a_01_1 = {d3 e6 89 74 24 58 89 d6 81 f6 98 41 3d 55 89 74 24 58 c7 44 24 44 00 00 00 00 c7 44 24 40 9f 50 ca 31 89 44 24 1c 89 54 24 18 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}