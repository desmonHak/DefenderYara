
rule Trojan_Win32_LummaStealer_GVQ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 01 1e ba 8a a5 08 00 8b 7d c8 03 fa 03 fb 03 f8 c7 45 a8 16 19 00 00 } //2
		$a_01_1 = {03 f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 b6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}