
rule Trojan_Win32_Guloader_GQJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 65 6e 6e 65 6d 66 61 72 74 20 75 6e 73 65 6c 6c 20 72 6f 6c 6c 65 72 73 } //1 gennemfart unsell rollers
		$a_81_1 = {66 69 73 6b 65 64 72 61 62 73 20 6c 67 65 62 65 73 67 65 74 73 20 69 6d 6d 6f 76 65 61 62 6c 79 } //1 fiskedrabs lgebesgets immoveably
		$a_81_2 = {75 6e 73 61 79 2e 65 78 65 } //1 unsay.exe
		$a_81_3 = {62 65 73 77 69 6e 67 65 20 70 69 63 6f 66 61 72 61 64 } //1 beswinge picofarad
		$a_81_4 = {61 6c 70 68 61 62 65 74 73 20 74 6f 72 73 64 61 67 73 6d 64 65 72 } //1 alphabets torsdagsmder
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}