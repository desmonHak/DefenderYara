
rule Trojan_Win32_LummaStealer_MK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f0 8b f3 f6 2f 47 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_MK_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 fb 31 f3 21 f2 09 da 83 e0 01 f7 d8 25 df b0 08 99 33 81 34 06 } //15
		$a_01_1 = {89 d0 21 c8 01 ca 01 c0 29 c2 89 d0 c1 e8 12 21 c1 01 d0 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}