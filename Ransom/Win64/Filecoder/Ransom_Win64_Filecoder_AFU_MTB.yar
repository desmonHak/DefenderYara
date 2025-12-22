
rule Ransom_Win64_Filecoder_AFU_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.AFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b8 0b 00 00 ?? ?? ?? ?? ?? ?? bf 01 00 00 00 31 f6 48 8b 55 ?? 48 89 d0 48 f7 d8 } //1
		$a_01_1 = {55 53 45 52 50 52 4f 46 49 4c 45 52 45 41 44 4d 45 2e 74 78 74 } //2 USERPROFILEREADME.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 63 61 6e 6e 6f 74 20 62 65 20 64 65 63 72 79 70 74 65 64 } //3 Your files are encrypted and cannot be decrypted
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}