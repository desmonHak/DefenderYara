
rule Ransom_Win32_FileCoder_MKF_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 4c 65 67 69 6f 6e 5c 44 65 73 6b 74 6f 70 5c 6c 61 73 74 62 75 74 6e 6f 74 6c 65 61 73 74 5c 52 65 6c 65 61 73 65 5c 6c 73 74 2e 70 64 62 } //4 Users\Legion\Desktop\lastbutnotleast\Release\lst.pdb
		$a_01_1 = {46 69 6c 65 20 64 65 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //3 File deleted successfully.
		$a_01_2 = {43 3a 5c 44 65 63 72 79 70 74 69 6f 6e 4b 65 79 5c 44 65 63 6f 64 65 2e 74 78 74 } //2 C:\DecryptionKey\Decode.txt
		$a_01_3 = {43 3a 5c 44 65 63 72 79 70 74 69 6f 6e 4b 65 79 5c 50 4b 65 79 2e 74 78 74 } //1 C:\DecryptionKey\PKey.txt
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}