
rule Trojan_Win32_VidarStealer_ZB_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //10 Google\Chrome\User Data
		$a_81_1 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //10 BraveSoftware\Brave-Browser\User Data
		$a_81_2 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //10 Microsoft\Edge\User Data
		$a_81_3 = {4b 65 79 20 64 65 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Key decrypted successfully
		$a_81_4 = {45 6e 63 72 79 70 74 65 64 20 6b 65 79 20 72 65 74 72 69 65 76 65 64 } //1 Encrypted key retrieved
		$a_81_5 = {46 6f 75 6e 64 20 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 Found encrypted_key
		$a_81_6 = {42 72 6f 77 73 65 72 20 6e 6f 74 20 64 65 74 65 63 74 65 64 } //1 Browser not detected
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=34
 
}