
rule Trojan_Win32_LummaStealer_GAPF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GAPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d ef 33 4d e0 8b 55 e4 88 0a 8b 45 f0 33 d2 b9 05 00 00 00 f7 f1 85 d2 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}