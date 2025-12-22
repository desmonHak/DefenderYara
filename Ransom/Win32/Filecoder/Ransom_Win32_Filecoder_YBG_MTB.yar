
rule Ransom_Win32_Filecoder_YBG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_1 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 2e 74 78 74 } //1 ransom_note.txt
		$a_03_2 = {59 6f 75 72 c7 85 ?? ?? ?? ?? 20 53 65 63 c7 85 ?? ?? ?? ?? 72 65 74 20 c7 85 ?? ?? ?? ?? 4b 65 79 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*5) >=7
 
}