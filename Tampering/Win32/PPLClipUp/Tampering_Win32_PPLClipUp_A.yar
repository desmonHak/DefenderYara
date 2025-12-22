
rule Tampering_Win32_PPLClipUp_A{
	meta:
		description = "Tampering:Win32/PPLClipUp.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6c 00 69 00 70 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 clipup.exe
		$a_00_1 = {20 00 2d 00 70 00 70 00 6c 00 20 00 } //1  -ppl 
		$a_00_2 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //-5 :\windows\
		$a_00_3 = {2e 00 74 00 6d 00 70 00 } //-5 .tmp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-5+(#a_00_3  & 1)*-5) >=2
 
}