
rule Trojan_Win32_GuLoader_SVP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 6e 61 74 74 65 72 67 61 6c 65 6e 65 5c 68 6f 76 65 64 6d 65 64 76 69 72 6b 65 6e 64 65 73 5c 69 6e 66 6f 72 6d 61 74 69 6f 6e 73 73 67 6e 69 6e 67 } //1 \nattergalene\hovedmedvirkendes\informationssgning
		$a_81_1 = {5c 70 69 6e 64 65 62 72 6e 64 65 5c 53 61 6e 67 65 72 66 65 73 74 31 30 31 2e 6c 6e 6b } //1 \pindebrnde\Sangerfest101.lnk
		$a_81_2 = {5c 6f 63 63 69 64 65 6e 74 61 6c 69 7a 65 64 5c 55 66 6f 72 64 72 61 67 65 6c 69 67 68 65 64 65 6e 73 2e 69 6e 69 } //1 \occidentalized\Ufordragelighedens.ini
		$a_81_3 = {5c 72 69 6e 67 73 74 65 64 65 72 5c 64 79 72 6c 67 65 72 6e 65 73 2e 6a 70 67 } //1 \ringsteder\dyrlgernes.jpg
		$a_81_4 = {5c 53 6c 62 6e 69 6e 67 65 6e 73 31 32 30 2e 6c 6e 6b } //1 \Slbningens120.lnk
		$a_81_5 = {5c 61 6d 70 65 72 65 6d 65 74 72 65 74 73 2e 62 69 6e } //1 \amperemetrets.bin
		$a_81_6 = {5c 73 76 72 64 6c 69 6c 6a 65 72 2e 68 74 6d } //1 \svrdliljer.htm
		$a_81_7 = {5c 61 72 65 61 6c 66 6f 72 68 6f 6c 64 5c 62 6c 61 64 67 72 6e 74 2e 64 6c 6c } //1 \arealforhold\bladgrnt.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}