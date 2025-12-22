
rule Trojan_Win32_ProcessHijack_AHB_MTB{
	meta:
		description = "Trojan:Win32/ProcessHijack.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 83 c0 10 ba d4 17 4b 1d 31 10 83 c0 04 e2 f9 } //10
		$a_01_1 = {0a d8 2e 9f 5f 08 28 2c 3e 4b a8 ad 0e 77 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}