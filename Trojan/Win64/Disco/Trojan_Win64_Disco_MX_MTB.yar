
rule Trojan_Win64_Disco_MX_MTB{
	meta:
		description = "Trojan:Win64/Disco.MX!MTB,SIGNATURE_TYPE_PEHSTR,25 00 25 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 4a 69 63 75 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 65 78 74 65 72 6e 61 6c 73 74 65 61 6c 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 65 78 74 65 72 6e 61 6c 73 74 65 61 6c 65 72 2e 70 64 62 } //30 C:\Users\Jicu\source\repos\externalstealer\x64\Release\externalstealer.pdb
		$a_01_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 } //1 discord.com/api/webhooks
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d } //1 taskkill /IM
		$a_01_3 = {59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //5 YandexBrowser\User Data\Default\Local Storage\leveldb
		$a_01_4 = {42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //5 Brave-Browser\User Data\Default\Local Storage\leveldb
		$a_01_5 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //5 Chrome\User Data\Default\Local Storage\leveldb
		$a_01_6 = {4f 70 65 72 61 } //5 Opera
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=37
 
}