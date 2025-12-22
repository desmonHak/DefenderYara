
rule Trojan_Win32_SalatStealer_SMX_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.SMX!MTB,SIGNATURE_TYPE_PEHSTR,21 00 21 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 } //20 Go build
		$a_01_1 = {41 72 6d 6f 72 79 45 78 6f 64 75 73 47 75 61 72 64 61 42 69 74 61 70 70 43 6f 69 6e 39 38 46 65 77 63 68 61 46 69 6e 6e 69 65 49 63 6f 6e 65 78 4b 61 69 6b 61 73 4f 78 79 67 65 6e 50 6f 6e 74 65 6d 53 61 74 75 72 6e 53 6f 6c 6c 65 74 57 6f 6d 62 61 74 58 4d 52 } //10 ArmoryExodusGuardaBitappCoin98FewchaFinnieIconexKaikasOxygenPontemSaturnSolletWombatXMR
		$a_01_2 = {43 68 72 6f 6d 65 43 68 65 64 6f 74 4b 6f 6d 65 74 61 46 65 6e 72 69 72 43 6f 6f 77 6f 6e 4c 69 65 62 61 6f 44 72 61 67 6f 6e 43 6f 63 43 6f 63 59 61 6e 64 65 78 } //10 ChromeChedotKometaFenrirCoowonLiebaoDragonCocCocYandex
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 } //1 GetClipboard
		$a_01_4 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c } //1 taskkill
		$a_01_6 = {42 72 6f 77 73 65 72 73 5c 43 6f 6f 6b 69 65 73 } //1 Browsers\Cookies
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=33
 
}