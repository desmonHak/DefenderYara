
rule Trojan_Win64_ValleyRat_GVC_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 02 48 8b 44 24 60 88 54 04 53 48 ff c0 48 83 f8 05 7d 1d 48 89 44 24 60 b8 3e 00 00 00 } //2
		$a_01_1 = {6d 61 69 6e 2e 43 68 61 43 68 61 32 30 44 65 63 72 79 70 74 } //1 main.ChaCha20Decrypt
		$a_01_2 = {43 68 61 43 68 61 32 30 45 6e 63 72 79 70 74 65 64 2e 74 78 74 } //1 ChaCha20Encrypted.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}