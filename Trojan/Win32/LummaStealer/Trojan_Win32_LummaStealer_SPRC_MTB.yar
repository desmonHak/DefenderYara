
rule Trojan_Win32_LummaStealer_SPRC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SPRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 20 20 20 20 00 50 36 00 00 70 8d 00 00 4a 36 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 20 20 20 20 20 20 20 20 00 10 00 00 00 c0 c3 00 00 02 00 00 00 4e 36 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 00 00 00 10 00 00 00 d0 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}