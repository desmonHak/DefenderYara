
rule Trojan_Win32_Lazy_MKF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 00 6c 00 61 00 64 00 69 00 6d 00 69 00 72 00 b5 00 f9 00 24 00 73 00 64 00 73 00 34 00 31 00 32 00 31 00 32 00 31 00 00 00 00 00 90 90 00 00 } //15
		$a_81_1 = {73 70 69 64 65 67 67 67 68 6a 24 2b 39 39 39 39 25 25 } //10 spideggghj$+9999%%
		$a_81_2 = {5c 77 69 6e 64 6f 77 73 75 70 64 61 74 65 5c 6d 73 65 72 76 69 63 65 2e 65 78 65 } //5 \windowsupdate\mservice.exe
		$a_81_3 = {2f 2f 62 20 2f 2f 6e 6f 6c 6f 67 6f } //3 //b //nologo
		$a_81_4 = {7b 43 4f 4e 54 52 4f 4c 44 4f 57 4e 7d 6c 7b 43 4f 4e 54 52 4f 4c 55 50 7d } //2 {CONTROLDOWN}l{CONTROLUP}
	condition:
		((#a_01_0  & 1)*15+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=35
 
}