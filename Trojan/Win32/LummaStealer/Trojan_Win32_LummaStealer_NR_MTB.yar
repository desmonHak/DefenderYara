
rule Trojan_Win32_LummaStealer_NR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe c9 8a 4d 02 81 c5 02 00 00 00 d2 ea } //2
		$a_01_1 = {32 d8 8d 44 04 0c 89 10 8d 64 24 0c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}