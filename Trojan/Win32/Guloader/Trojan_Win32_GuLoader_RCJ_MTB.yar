
rule Trojan_Win32_GuLoader_RCJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 70 72 6f 74 65 73 65 6e 5c 6b 65 6e 64 69 6e 67 73 73 69 67 6e 61 6c 65 72 } //1 \protesen\kendingssignaler
		$a_81_1 = {5c 73 63 69 65 6e 74 6f 6c 69 73 6d 5c 6f 70 6c 73 6e 69 6e 67 65 72 6e 65 73 2e 62 69 6e } //1 \scientolism\oplsningernes.bin
		$a_81_2 = {25 4f 72 64 76 65 6b 73 6c 69 6e 67 65 6e 73 25 5c 69 6e 61 64 76 65 72 74 61 6e 74 5c 62 69 6c 6c 61 72 64 6b 75 67 6c 65 72 6e 65 } //1 %Ordvekslingens%\inadvertant\billardkuglerne
		$a_81_3 = {46 72 65 6d 74 69 64 73 66 6f 72 73 6b 65 72 65 6e 33 35 2e 69 6e 69 } //1 Fremtidsforskeren35.ini
		$a_81_4 = {51 75 61 6e 74 61 20 53 65 72 76 69 63 65 73 20 49 6e 63 2e } //1 Quanta Services Inc.
		$a_81_5 = {70 61 63 68 79 67 6c 6f 73 73 6f 75 73 2e 65 78 65 } //1 pachyglossous.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}