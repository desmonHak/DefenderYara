
rule Trojan_Win32_LummaStealer_GPAT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 1f 72 61 d2 9c 11 0c 17 58 13 0c 11 09 17 58 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}