
rule Trojan_Win32_LummaStealer_AHD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 01 0e 00 00 f0 04 00 00 94 00 00 00 ?? ?? ?? ?? ?? ?? 00 00 10 00 } //20
		$a_01_1 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 e2 05 } //30
		$a_01_2 = {20 20 20 00 20 20 20 20 00 d0 05 00 00 10 00 00 00 d0 05 00 00 10 } //50
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*30+(#a_01_2  & 1)*50) >=100
 
}