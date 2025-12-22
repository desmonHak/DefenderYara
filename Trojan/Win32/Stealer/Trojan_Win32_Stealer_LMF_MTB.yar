
rule Trojan_Win32_Stealer_LMF_MTB{
	meta:
		description = "Trojan:Win32/Stealer.LMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 93 00 00 00 b9 c2 05 00 00 ba f2 7f 7d fd 30 10 40 49 } //20
		$a_01_1 = {0d 87 fa 1a 80 f2 f2 f2 79 4f fa f2 f2 f2 c1 3b 73 00 df 77 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}