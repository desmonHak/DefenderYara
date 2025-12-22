
rule Ransom_Win32_Filecoder_MAV_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //4 Your files have been encrypted
		$a_81_1 = {46 69 6c 65 20 65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //3 File encrypted successfully
		$a_81_2 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 73 65 6e 64 } //2 To decrypt your files, send
		$a_81_3 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=10
 
}