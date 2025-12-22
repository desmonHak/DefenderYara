
rule Trojan_Win32_GuLoader_SUJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 6c 75 6d 62 65 72 6d 61 6e 2e 69 6e 69 } //1 \lumberman.ini
		$a_81_1 = {70 61 74 63 68 77 6f 72 6b 79 5c 55 6e 62 65 76 65 6c 65 64 } //1 patchworky\Unbeveled
		$a_81_2 = {63 68 69 6e 67 6d 61 5c 55 6e 69 6e 73 74 61 6c 6c 5c 70 72 65 72 65 76 69 73 65 64 5c 4b 61 64 61 76 65 72 36 37 } //1 chingma\Uninstall\prerevised\Kadaver67
		$a_81_3 = {5c 61 72 74 5c 50 68 61 72 79 6e 67 65 73 2e 6c 6e 6b } //1 \art\Pharynges.lnk
		$a_81_4 = {5c 70 6c 6f 74 74 69 6e 67 5c 67 6c 6f 73 73 65 72 65 64 65 2e 64 6c 6c } //1 \plotting\glosserede.dll
		$a_81_5 = {67 69 76 69 6e 67 6c 79 5c 48 75 73 73 74 76 5c 63 65 6e 74 72 69 66 75 67 61 6c 73 70 72 65 64 65 72 65 6e } //1 givingly\Husstv\centrifugalsprederen
		$a_81_6 = {42 65 65 68 69 76 65 5c 66 6c 6c 65 73 68 75 73 65 73 5c 50 68 6f 74 6f 70 69 63 } //1 Beehive\flleshuses\Photopic
		$a_81_7 = {5c 69 6e 61 70 70 65 74 65 6e 63 65 5c 62 69 70 6c 61 6e 65 72 6e 65 5c 4b 61 6d 75 66 6c 65 72 65 6e 64 65 73 2e 67 69 66 } //1 \inappetence\biplanerne\Kamuflerendes.gif
		$a_81_8 = {5c 4e 65 64 73 6c 61 61 65 64 65 73 31 37 34 5c 73 74 61 74 73 67 61 72 61 6e 74 69 65 6e 73 2e 69 6e 69 } //1 \Nedslaaedes174\statsgarantiens.ini
		$a_81_9 = {5c 75 73 73 65 6c 68 65 64 65 6e 5c 74 61 67 70 61 70 70 65 6e 73 2e 69 6e 69 } //1 \usselheden\tagpappens.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}