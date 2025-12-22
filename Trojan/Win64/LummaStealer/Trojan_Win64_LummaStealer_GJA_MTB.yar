
rule Trojan_Win64_LummaStealer_GJA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Microsoft\Edge\User Data\Default\Login Data
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 70 61 73 73 77 6f 72 64 73 } //1 C:\Windows\Temp\passwords
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 } //1 shutdown /r /t
		$a_01_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Google\Chrome\User Data\Default\Login Data
		$a_01_4 = {43 3a 5c 50 75 62 6c 69 63 5c 64 65 63 6f 79 2e 6c 6e 6b } //1 C:\Public\decoy.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}