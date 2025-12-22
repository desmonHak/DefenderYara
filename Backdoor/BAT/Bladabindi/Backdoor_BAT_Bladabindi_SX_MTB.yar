
rule Backdoor_BAT_Bladabindi_SX_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 61 32 36 64 32 66 61 37 2d 32 66 30 34 2d 34 66 65 65 2d 38 30 65 65 2d 35 65 64 64 64 65 33 36 61 66 66 37 } //1 $a26d2fa7-2f04-4fee-80ee-5eddde36aff7
		$a_81_1 = {48 6f 73 74 20 70 72 6f 63 65 73 73 20 66 6f 72 20 77 69 6e 64 6f 77 73 20 54 61 73 6b 73 } //1 Host process for windows Tasks
		$a_81_2 = {73 63 73 76 68 6f 73 74 2e 65 78 65 } //1 scsvhost.exe
		$a_81_3 = {63 32 4e 7a 64 6d 68 76 63 33 51 6b } //1 c2Nzdmhvc3Qk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}