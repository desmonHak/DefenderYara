
rule Trojan_BAT_ClipBanker_AR_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f ?? 00 00 0a 7e ?? 00 00 04 07 7e ?? 00 00 04 8e 69 5d 91 61 28 ?? 00 00 0a 6f ?? 00 00 0a 26 07 17 58 0b 07 02 6f } //2
		$a_01_1 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //1 AddClipboardFormatListener
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_ClipBanker_AR_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 26 00 00 0a 2d 05 dd 86 00 00 00 28 27 00 00 0a 0a 06 28 28 00 00 0a 2d 0d 06 7e 2c 00 00 04 28 1c 00 00 0a 2c 02 de 69 06 28 02 00 00 06 28 01 00 00 06 1b 6f 29 00 00 0a 2d 25 06 28 03 00 00 06 } //10
		$a_01_1 = {07 08 06 08 91 7e 33 00 00 04 08 7e 33 00 00 04 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 df } //8
		$a_01_2 = {49 4c 6f 76 65 59 6f 75 72 4d 6f 74 68 65 72 } //2 ILoveYourMother
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*2) >=20
 
}