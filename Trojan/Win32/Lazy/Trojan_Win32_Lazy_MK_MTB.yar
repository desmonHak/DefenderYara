
rule Trojan_Win32_Lazy_MK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 e2 05 } //10
		$a_01_1 = {20 20 20 00 20 20 20 20 00 d0 05 00 00 10 00 00 00 d0 05 00 00 10 } //10
		$a_03_2 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? 02 00 00 00 e0 05 00 00 02 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}