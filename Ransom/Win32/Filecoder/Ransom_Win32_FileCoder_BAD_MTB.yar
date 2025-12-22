
rule Ransom_Win32_FileCoder_BAD_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 49 63 65 70 69 63 6b 20 70 61 79 6c 6f 61 64 20 65 78 65 63 75 74 65 64 } //1 -MpPreference -DisableRealtimeMonitoring $trueIcepick payload executed
		$a_81_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 41 45 53 } //1 Your files are encrypted with AES
		$a_81_3 = {50 61 79 20 24 31 30 30 30 20 69 6e 20 42 69 74 63 6f 69 6e 20 74 6f } //1 Pay $1000 in Bitcoin to
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}