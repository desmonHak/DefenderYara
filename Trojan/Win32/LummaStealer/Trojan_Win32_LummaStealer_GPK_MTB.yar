
rule Trojan_Win32_LummaStealer_GPK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 02 00 00 00 b3 bc e1 05 00 00 00 00 9d cf d1 05 00 00 00 00 00 a6 39 00 f7 5f 44 de 21 71 d1 05 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}