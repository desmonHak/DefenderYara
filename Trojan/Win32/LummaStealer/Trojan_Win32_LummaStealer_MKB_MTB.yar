
rule Trojan_Win32_LummaStealer_MKB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c7 8a 84 24 74 01 00 00 88 84 24 34 02 00 00 c6 84 24 26 01 00 00 6a c6 84 24 27 01 00 00 fb c6 84 24 28 01 00 00 67 } //15
		$a_01_1 = {89 d0 09 d8 21 da 29 d0 89 cb f7 d3 21 c3 89 c2 f7 d2 21 ca 0f af d3 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}