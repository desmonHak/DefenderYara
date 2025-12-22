
rule Trojan_Win32_Tiny_PPG_MTB{
	meta:
		description = "Trojan:Win32/Tiny.PPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 20 41 72 65 20 46 75 63 6b 65 64 2c 20 59 6f 75 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 69 73 20 6e 6f 77 20 6f 75 72 73 2c 20 59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 77 20 65 6e 63 72 79 70 74 65 64 2c 20 4e 6f 77 20 73 74 61 72 74 20 68 75 66 66 69 6e 67 20 74 68 65 20 63 6f 70 69 75 6d } //4 You Are Fucked, Your information is now ours, Your files are now encrypted, Now start huffing the copium
		$a_02_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-70] 2e 00 65 00 78 00 65 00 } //1
		$a_02_2 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-70] 2e 65 78 65 } //1
	condition:
		((#a_81_0  & 1)*4+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=5
 
}