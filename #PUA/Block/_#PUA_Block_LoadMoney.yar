
rule _#PUA_Block_LoadMoney{
	meta:
		description = "!#PUA:Block:LoadMoney,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 8a 08 83 c1 ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 88 0a eb 90 09 19 00 8b 4d ?? 83 c1 ?? 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? a1 ?? ?? ?? ?? 03 45 } //1
		$a_02_1 = {33 c0 8a 02 83 c0 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb 90 09 1a 00 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 3b 4d ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 55 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule _#PUA_Block_LoadMoney_2{
	meta:
		description = "!#PUA:Block:LoadMoney,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 62 69 6e 75 70 64 61 74 65 2e 6d 61 69 6c 2e 72 75 } //1 //binupdate.mail.ru
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 69 00 6c 00 2e 00 52 00 75 00 5c 00 41 00 67 00 65 00 6e 00 74 00 } //1 Software\Mail.Ru\Agent
		$a_01_2 = {6e 6f 74 6f 6f 6c 62 61 72 } //1 notoolbar
		$a_01_3 = {70 61 72 74 6e 65 72 5f 6f 6e 6c 69 6e 65 5f 75 72 6c } //1 partner_online_url
		$a_01_4 = {65 78 65 2e 61 67 65 6e 74 2e 6d 61 69 6c 2e 72 75 2f 73 70 75 74 6e 69 6b 2f 6d 61 69 6c 72 75 73 70 75 74 6e 69 6b 2e 65 78 65 } //1 exe.agent.mail.ru/sputnik/mailrusputnik.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}