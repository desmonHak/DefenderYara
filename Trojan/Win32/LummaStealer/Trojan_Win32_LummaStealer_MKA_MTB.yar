
rule Trojan_Win32_LummaStealer_MKA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 f2 01 d1 0f b6 7d ?? 01 d7 01 f9 89 c6 83 e6 ?? 83 f0 ?? 8d 14 70 83 c5 08 8d 34 70 83 c6 ?? 89 d0 39 de } //15
		$a_01_1 = {89 d8 c1 e8 04 89 dd f7 d5 83 cd 0f 01 eb 43 c1 ef 04 31 df } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}