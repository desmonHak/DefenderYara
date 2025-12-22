
rule _#HSTR_MSIL_AgentTesla_AQ{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 73 74 75 62 5c 65 6f 70 79 45 78 5c 61 63 68 69 79 4d 65 7b 5c 4f 63 68 69 69 5f 75 69 5c 6f 62 6a 6e 52 65 6c 65 71 73 77 5c 6b 69 6c 6f 2e } //\stub\eopyEx\achiyMe{\Ochii_ui\objnReleqsw\kilo.  1
		$a_80_1 = {6c 70 4e 77 77 46 69 6c 75 4e 73 6d 65 } //lpNwwFiluNsme  1
		$a_80_2 = {52 78 61 64 62 62 6a 78 63 74 64 72 72 74 79 } //Rxadbbjxctdrrty  1
		$a_80_3 = {64 64 67 72 73 74 75 66 65 73 2e 65 78 65 } //ddgrstufes.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_2{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 46 58 49 56 5f 4e 65 78 75 73 5f 50 72 6f 67 72 65 73 73 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 FFXIV_Nexus_Progress.My.Resources
		$a_01_1 = {46 46 58 49 56 5f 4e 65 78 75 73 5f 50 72 6f 67 72 65 73 73 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 FFXIV_Nexus_Progress.Main.resources
		$a_01_2 = {46 46 58 49 56 5f 4e 65 78 75 73 5f 50 72 6f 67 72 65 73 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FFXIV_Nexus_Progress.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_3{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 52 46 59 51 5a 74 59 63 4b 78 72 6d 57 47 55 74 67 4d 6e 4f 4e 6c 77 45 4e 47 72 } //1 bRFYQZtYcKxrmWGUtgMnONlwENGr
		$a_01_1 = {52 75 64 61 77 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 RudawCore.Properties.Resources.resources
		$a_01_2 = {72 51 51 76 57 56 55 4c 50 4c 59 75 6b 4e 4a 68 } //1 rQQvWVULPLYukNJh
		$a_01_3 = {53 51 55 46 71 78 54 63 63 73 6b 44 53 42 57 47 55 68 45 73 } //1 SQUFqxTccskDSBWGUhEs
		$a_01_4 = {73 72 6e 79 6a 65 6a 6e 65 74 64 6e 72 74 73 67 78 7a 67 64 74 6a 7a 6a 64 67 } //1 srnyjejnetdnrtsgxzgdtjzjdg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_4{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 37 61 35 63 76 77 72 39 33 34 65 71 79 7a 23 53 79 73 } //1 x7a5cvwr934eqyz#Sys
		$a_01_1 = {32 33 31 30 32 37 39 30 43 36 43 46 44 42 32 43 35 31 39 39 42 35 41 34 35 37 38 38 38 45 31 34 39 45 41 34 32 42 38 41 43 33 37 45 36 34 46 37 32 33 42 37 39 32 38 33 31 33 46 30 33 46 32 36 } //1 23102790C6CFDB2C5199B5A457888E149EA42B8AC37E64F723B7928313F03F26
		$a_03_2 = {6f 75 72 63 [0-03] 6f 52 65 } //1
		$a_01_3 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_4 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_5{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 75 61 6e 74 75 6d 43 68 65 73 73 49 54 32 2e 66 72 6d 4d 61 69 6e 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 QuantumChessIT2.frmMainMenu.resources
		$a_01_1 = {51 75 61 6e 74 75 6d 43 68 65 73 73 49 54 32 2e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 QuantumChessIT2.Game.resources
		$a_01_2 = {51 75 61 6e 74 75 6d 43 68 65 73 73 49 54 32 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 QuantumChessIT2.Resources.resources
		$a_01_3 = {51 75 61 6e 74 75 6d 43 68 65 73 73 49 54 32 2e 50 69 63 74 75 72 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 QuantumChessIT2.PictureForm.resources
		$a_01_4 = {51 75 61 6e 74 75 6d 43 68 65 73 73 49 54 32 2e 50 6c 61 79 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 QuantumChessIT2.PlayMenu.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_6{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 75 4a 69 6e 67 75 61 6e 67 3b 5a 65 6a 65 } //1 HuJinguang;Zeje
		$a_01_1 = {43 78 46 6c 61 74 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CxFlatUI.Properties.Resources.resources
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_3 = {53 65 74 42 61 73 65 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 SetBasePasswordChar
		$a_01_4 = {43 78 46 6c 61 74 55 49 2e 55 53 47 46 49 2e 72 65 73 6f 75 72 63 65 73 } //1 CxFlatUI.USGFI.resources
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_7{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 69 72 65 63 74 58 2e 44 69 72 65 63 74 33 44 58 2e 55 73 65 72 49 6e 74 65 72 66 61 63 65 2e 46 6f 72 6d 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 DirectX.Direct3DX.UserInterface.FormGame.resources
		$a_01_1 = {44 69 72 65 63 74 58 2e 44 69 72 65 63 74 33 44 58 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 DirectX.Direct3DX.Properties.Resources.resources
		$a_01_2 = {5f 5f 5f 61 5f 5f 5f 62 63 63 } //5 ___a___bcc
		$a_01_3 = {4e 6f 74 49 6d 70 6c 65 6d 65 6e 74 65 64 45 78 63 65 70 74 69 6f 6e } //1 NotImplementedException
		$a_01_4 = {52 65 6d 6f 76 65 } //1 Remove
		$a_01_5 = {65 53 6f 6c 64 69 65 72 44 69 72 65 63 74 69 6f 6e } //1 eSoldierDirection
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_8{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 GeneratedCodeAttribute
		$a_01_1 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //1 System.CodeDom.Compiler
		$a_01_2 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 EditorBrowsableAttribute
		$a_01_3 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 EditorBrowsableState
		$a_01_4 = {4a 6f 68 61 6e 6e 2e 6d 61 69 6e 57 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Johann.mainWin.resources
		$a_01_5 = {46 72 69 65 64 72 69 63 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Friedrich.Properties.Resources.resources
		$a_01_6 = {53 79 73 74 65 6d 2e 47 6c 6f 62 61 6c 69 7a 61 74 69 6f 6e } //1 System.Globalization
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_9{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {38 42 32 32 35 35 39 38 35 45 36 37 33 46 46 37 38 33 41 42 46 35 30 33 37 31 45 38 31 34 41 46 35 45 31 34 37 30 37 30 46 46 37 33 41 42 31 32 45 32 34 39 34 33 43 39 44 45 46 38 45 33 31 43 } //1 8B2255985E673FF783ABF50371E814AF5E147070FF73AB12E24943C9DEF8E31C
		$a_01_1 = {30 46 33 41 37 36 42 38 32 32 39 39 44 46 36 36 33 41 30 31 44 35 34 46 43 38 39 46 34 45 31 37 42 41 31 33 42 34 30 30 44 46 34 32 37 32 45 34 38 42 33 45 43 44 42 37 30 30 43 42 45 39 36 44 } //1 0F3A76B82299DF663A01D54FC89F4E17BA13B400DF4272E48B3ECDB700CBE96D
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {41 70 70 65 6e 64 } //1 Append
		$a_01_4 = {4c 6f 61 64 43 6f 6d 70 6f 6e 65 6e 74 } //1 LoadComponent
		$a_01_5 = {4d 6f 76 65 4e 65 78 74 } //1 MoveNext
		$a_00_6 = {70 00 61 00 67 00 65 00 31 00 2e 00 62 00 61 00 6d 00 6c 00 } //1 page1.baml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_10{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 69 6e 74 31 2e 43 75 73 74 6f 6d 43 6f 6c 6f 72 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Paint1.CustomColorDialog.resources
		$a_01_1 = {50 61 69 6e 74 31 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Paint1.Form1.resources
		$a_01_2 = {50 61 69 6e 74 49 74 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 PaintIt.Main.resources
		$a_01_3 = {50 61 69 6e 74 49 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PaintIt.Properties.Resources.resources
		$a_01_4 = {50 61 69 6e 74 49 74 2e 53 63 72 65 65 6e 4f 76 65 72 6c 61 79 2e 72 65 73 6f 75 72 63 65 73 } //1 PaintIt.ScreenOverlay.resources
		$a_03_5 = {0a 00 00 19 8d ?? ?? ?? 01 0a 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0a 02 06 28 ?? ?? ?? 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_11{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 6c 59 46 56 4e 74 52 45 4c 5a 79 75 49 6f 46 76 47 6d 76 72 70 62 75 64 73 67 44 47 62 4a 4b 72 } //1 get_lYFVNtRELZyuIoFvGmvrpbudsgDGbJKr
		$a_03_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 43 6c 69 65 6e 74 5c 54 65 6d 70 5c 53 50 53 67 6b 42 76 4f 58 45 5c 73 72 63 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c [0-0f] 2e 70 64 62 } //1
		$a_00_2 = {51 00 75 00 65 00 73 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 64 00 61 00 74 00 } //1 Questions.dat
		$a_00_3 = {6c 00 59 00 46 00 56 00 4e 00 74 00 52 00 45 00 4c 00 5a 00 79 00 75 00 49 00 6f 00 46 00 76 00 47 00 6d 00 76 00 72 00 70 00 62 00 75 00 64 00 73 00 67 00 44 00 47 00 62 00 4a 00 4b 00 72 00 } //1 lYFVNtRELZyuIoFvGmvrpbudsgDGbJKr
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_12{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {21 63 51 43 42 45 51 41 42 67 41 43 49 67 41 43 49 67 41 43 49 67 41 43 49 67 41 } //1 !cQCBEQABgACIgACIgACIgACIgA
		$a_01_1 = {21 51 49 76 5a 6d 62 4a 52 58 59 74 4a 33 62 47 4a 58 5a 69 31 57 64 4f 35 69 62 76 6c 47 64 68 70 58 61 73 46 6d 59 76 78 32 52 75 30 57 5a 30 4e 58 65 54 56 43 41 } //1 !QIvZmbJRXYtJ3bGJXZi1WdO5ibvlGdhpXasFmYvx2Ru0WZ0NXeTVCA
		$a_01_2 = {21 34 47 41 76 42 51 61 41 4d 48 41 79 42 51 5a 41 59 46 41 67 41 51 65 41 77 47 41 69 42 51 62 41 55 47 41 7a 42 77 63 41 45 45 41 42 41 41 43 41 67 44 41 } //1 !4GAvBQaAMHAyBQZAYFAgAQeAwGAiBQbAUGAzBwcAEEABAACAgDA
		$a_01_3 = {21 51 59 41 51 48 41 79 42 51 59 41 41 48 41 54 42 } //1 !QYAQHAyBQYAAHATB
		$a_01_4 = {21 67 62 41 38 47 41 70 42 41 64 41 45 47 41 73 42 77 63 41 34 47 41 68 42 67 63 41 51 46 41 } //1 !gbA8GApBAdAEGAsBwcA4GAhBgcAQFA
		$a_01_5 = {4d 61 74 68 51 75 69 7a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MathQuiz.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_13{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 73 73 41 6e 61 6c 79 73 65 72 2e 53 61 74 65 6c 6c 69 74 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ChessAnalyser.Satellite.Properties.Resources.resources
		$a_01_1 = {43 68 65 73 73 41 6e 61 6c 79 73 65 72 2e 53 61 74 65 6c 6c 69 74 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 ChessAnalyser.Satellite.Properties
		$a_01_2 = {43 68 65 73 73 41 6e 61 6c 79 73 65 72 2e 45 78 70 6c 6f 72 65 72 2e 52 75 6c 65 73 } //1 ChessAnalyser.Explorer.Rules
		$a_01_3 = {43 68 65 73 73 41 6e 61 6c 79 73 65 72 2e 53 61 74 65 6c 6c 69 74 65 2e 50 47 4e 2e 44 6f 77 6e 6c 6f 61 64 65 72 73 } //1 ChessAnalyser.Satellite.PGN.Downloaders
		$a_01_4 = {53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 49 45 6e 75 6d 65 72 61 74 6f 72 2e 52 65 73 65 74 } //1 System.Collections.IEnumerator.Reset
		$a_03_5 = {06 0b 06 fe [0-04] 06 73 [0-03] 0a 73 [0-03] 0a 0c 08 6f [0-03] 0a 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*5) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_14{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  1
		$a_80_1 = {41 63 63 65 73 73 65 64 54 68 72 6f 75 67 68 50 72 6f 70 65 72 74 79 41 74 74 72 69 62 75 74 65 } //AccessedThroughPropertyAttribute  1
		$a_80_2 = {38 36 37 33 36 2e 72 65 73 6f 75 72 63 65 73 } //86736.resources  1
		$a_80_3 = {43 4b 6b 42 4c 48 68 42 64 70 62 7a 74 57 4d 76 4f 67 41 64 54 6d 58 4d 74 75 52 76 } //CKkBLHhBdpbztWMvOgAdTmXMtuRv  1
		$a_00_4 = {33 00 30 00 41 00 46 00 30 00 30 00 43 00 45 00 43 00 36 00 38 00 38 00 38 00 42 00 42 00 30 00 32 00 38 00 31 00 33 00 30 00 37 00 43 00 36 00 36 00 45 00 38 00 46 00 39 00 46 00 30 00 37 00 39 00 38 00 39 00 31 00 34 00 45 00 45 00 37 00 30 00 42 00 42 00 42 00 44 00 31 00 36 00 42 00 37 00 31 00 34 00 36 00 41 00 37 00 34 00 46 00 32 00 43 00 43 00 45 00 38 00 30 00 41 00 46 00 } //1 30AF00CEC6888BB0281307C66E8F9F0798914EE70BBBD16B7146A74F2CCE80AF
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_15{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 53 41 43 43 45 53 53 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.Form1.resources
		$a_01_1 = {4d 53 41 43 43 45 53 53 2e 6f 5f 70 72 6f 67 72 61 6d 69 65 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.o_programie.resources
		$a_01_2 = {4d 53 41 43 43 45 53 53 2e 52 47 42 46 69 6c 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.RGBFilter.resources
		$a_01_3 = {4d 53 41 43 43 45 53 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.Properties.Resources.resources
		$a_01_4 = {4d 53 41 43 43 45 53 53 2e 42 51 50 61 69 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.BQPaint.resources
		$a_01_5 = {4d 53 41 43 43 45 53 53 2e 6e 65 77 5f 66 69 6c 65 5f 77 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //1 MSACCESS.new_file_window.resources
		$a_03_6 = {00 03 2c 0b 02 7b ?? ?? ?? 04 14 fe 03 2b 01 16 0a 06 2c 0e 00 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 00 02 03 28 ?? ?? ?? 0a 00 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_16{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 6f 72 6c 64 4f 6e 65 2e 43 43 6f 6e 73 6f 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.CConsole.resources
		$a_01_1 = {57 6f 72 6c 64 4f 6e 65 2e 66 72 6d 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.frmGame.resources
		$a_01_2 = {57 6f 72 6c 64 4f 6e 65 2e 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.Instructions.resources
		$a_01_3 = {57 6f 72 6c 64 4f 6e 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.Resources.resources
		$a_01_4 = {57 6f 72 6c 64 4f 6e 65 2e 53 74 61 72 74 53 63 72 65 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.StartScreen.resources
		$a_01_5 = {57 6f 72 6c 64 4f 6e 65 2e 53 74 6f 72 65 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.Store.resources
		$a_01_6 = {57 6f 72 6c 64 4f 6e 65 2e 57 61 76 65 45 64 69 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.WaveEditor.resources
		$a_01_7 = {57 6f 72 6c 64 4f 6e 65 2e 57 61 76 65 52 65 77 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //1 WorldOne.WaveReward.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_17{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 GeneratedCodeAttribute
		$a_01_1 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //1 System.CodeDom.Compiler
		$a_01_2 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 EditorBrowsableAttribute
		$a_01_3 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 EditorBrowsableState
		$a_01_4 = {53 54 41 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 } //1 STAThreadAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_6 = {31 46 44 36 36 39 41 36 33 34 43 35 30 43 43 37 30 46 45 41 44 38 36 30 36 41 35 35 38 43 45 36 46 46 42 43 35 44 39 35 34 31 34 39 39 30 44 41 37 32 38 31 43 41 32 35 44 33 38 35 43 42 35 42 } //1 1FD669A634C50CC70FEAD8606A558CE6FFBC5D95414990DA7281CA25D385CB5B
		$a_01_7 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsApplication1.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_18{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_03_0 = {1f 3f 61 0d 38 ?? ?? ?? 00 11 04 1f 3a 61 13 04 38 ?? ?? ?? 00 11 05 1f 3b 61 } //1
		$a_03_1 = {26 1f f3 13 06 38 ?? ?? ?? ff 1f 25 28 ?? ?? ?? 06 13 05 1f 2e 28 90 1b 01 06 } //1
		$a_01_2 = {51 55 49 5a 5f 47 41 4d 45 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.My.Resources
		$a_01_3 = {51 55 49 5a 5f 47 41 4d 45 2e 41 62 6f 75 74 42 6f 78 31 2e 72 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.AboutBox1.resources
		$a_01_4 = {51 55 49 5a 5f 47 41 4d 45 2e 64 62 2e 72 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.db.resources
		$a_01_5 = {51 55 49 5a 5f 47 41 4d 45 2e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.Game.resources
		$a_01_6 = {51 55 49 5a 5f 47 41 4d 45 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.Resources.resources
		$a_01_7 = {51 55 49 5a 5f 47 41 4d 45 2e 4d 61 69 6e 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 QUIZ_GAME.MainMenu.resources
		$a_01_8 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_19{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 73 77 65 65 70 65 72 2e 50 69 63 74 75 72 65 52 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 minesweeper.PictureRes.resources
		$a_01_1 = {6d 69 6e 65 73 77 65 65 70 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 minesweeper.Resources.resources
		$a_01_2 = {6d 69 6e 65 73 77 65 65 70 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 minesweeper.Form1.resources
		$a_01_3 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_4 = {53 70 65 63 69 61 6c 44 69 72 65 63 74 6f 72 69 65 73 50 72 6f 78 79 } //1 SpecialDirectoriesProxy
		$a_01_5 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_01_6 = {61 64 64 65 64 48 61 6e 64 6c 65 72 4c 6f 63 6b 4f 62 6a 65 63 74 } //1 addedHandlerLockObject
		$a_01_7 = {61 64 64 5f 4c 6f 61 64 } //1 add_Load
		$a_01_8 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_01_9 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Dispose__Instance__
		$a_01_10 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //1 ShutdownMode
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=14
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_20{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {37 46 32 36 42 32 33 42 34 43 36 32 36 41 31 44 44 30 36 37 35 44 44 33 38 31 33 39 37 32 37 44 46 41 35 45 45 34 41 37 44 36 45 33 38 36 34 44 34 30 31 38 32 30 30 41 41 34 39 37 39 38 34 37 } //5 7F26B23B4C626A1DD0675DD38139727DFA5EE4A7D6E3864D4018200AA4979847
		$a_01_1 = {33 32 36 66 66 33 38 62 34 39 31 35 34 65 37 63 62 64 63 36 32 33 62 37 39 65 63 38 34 36 30 39 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //5 326ff38b49154e7cbdc623b79ec84609.Resources.resources
		$a_01_2 = {41 73 73 65 6d 62 6c 79 50 72 6f 64 75 63 74 41 74 74 72 69 62 75 74 65 } //1 AssemblyProductAttribute
		$a_01_3 = {41 73 73 65 6d 62 6c 79 43 6f 70 79 72 69 67 68 74 41 74 74 72 69 62 75 74 65 } //1 AssemblyCopyrightAttribute
		$a_01_4 = {41 73 73 65 6d 62 6c 79 43 6f 6d 70 61 6e 79 41 74 74 72 69 62 75 74 65 } //1 AssemblyCompanyAttribute
		$a_01_5 = {52 75 6e 74 69 6d 65 43 6f 6d 70 61 74 69 62 69 6c 69 74 79 41 74 74 72 69 62 75 74 65 } //1 RuntimeCompatibilityAttribute
		$a_01_6 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 56 65 72 73 69 6f 6e 69 6e 67 } //1 System.Runtime.Versioning
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_21{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_3 = {4d 6f 76 69 6e 67 53 74 61 72 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 MovingStars.Form1.resources
		$a_01_4 = {74 65 73 74 33 47 55 49 4d 6f 64 61 6c 46 6f 72 6d 2e 6d 6f 64 61 6c 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 test3GUIModalForm.modalForm.resources
		$a_01_5 = {50 6c 61 6e 65 74 73 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Planets.frmMain.resources
		$a_01_6 = {4d 6f 76 69 6e 67 53 74 61 72 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MovingStars.Properties.Resources.resources
		$a_01_7 = {43 6f 6e 63 61 74 } //1 Concat
		$a_01_8 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_9 = {67 65 74 5f 52 65 61 64 4d 65 } //1 get_ReadMe
		$a_01_10 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_11 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_01_12 = {52 65 61 64 4b 65 79 } //1 ReadKey
		$a_01_13 = {43 6f 6e 73 6f 6c 65 4b 65 79 } //1 ConsoleKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_22{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //1 System.CodeDom.Compiler
		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_2 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 EditorBrowsableAttribute
		$a_01_3 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 EditorBrowsableState
		$a_01_4 = {61 67 65 63 61 6c 63 75 6c 61 74 6f 72 2e 52 61 74 65 53 65 72 76 69 63 65 57 65 62 52 65 66 65 72 65 6e 63 65 } //1 agecalculator.RateServiceWebReference
		$a_01_5 = {61 67 65 63 61 6c 63 75 6c 61 74 6f 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 agecalculator.Form1.resources
		$a_01_6 = {61 67 65 63 61 6c 63 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 agecalculator.Properties.Resources.resources
		$a_01_7 = {4c 6f 61 64 53 65 72 76 69 63 65 43 6f 64 65 73 } //1 LoadServiceCodes
		$a_01_8 = {50 61 72 73 65 52 61 74 65 73 52 65 73 70 6f 6e 73 65 4d 65 73 73 61 67 65 } //1 ParseRatesResponseMessage
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_23{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 55 49 2e 53 79 73 74 65 6d 5f } //1 HotelManagementUI.System_
		$a_01_1 = {46 6f 72 6d 4d 61 69 6e 5f 4c 6f 61 64 } //1 FormMain_Load
		$a_01_2 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
		$a_01_3 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 55 49 2e 53 79 73 74 65 6d 5f 2e 46 6f 72 6d 50 73 4d 6f 64 69 66 79 2e 72 65 73 6f 75 72 63 65 73 } //1 HotelManagementUI.System_.FormPsModify.resources
		$a_01_4 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 55 49 2e 52 6f 6f 6d 65 72 2e 46 6f 72 6d 52 6f 6f 6d 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 HotelManagementUI.Roomer.FormRoomer.resources
		$a_01_5 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 55 49 2e 76 31 2e 72 65 73 6f 75 72 63 65 73 } //1 HotelManagementUI.v1.resources
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } //1 ReverseString
		$a_03_8 = {00 16 0d 00 06 07 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0 08 6f ?? ?? ?? 0a 13 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1) >=9
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_24{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {4b 61 63 68 6f 75 2e 46 6f 72 6d 4b 61 63 68 6f 75 2e 72 65 73 6f 75 72 63 65 73 } //1 Kachou.FormKachou.resources
		$a_01_1 = {4e 6f 6b 6f 72 69 6d 6f 6e 6f 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Nokorimono.MainForm.resources
		$a_01_2 = {4b 6f 6b 65 74 73 75 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.MDIParent1.resources
		$a_01_3 = {4b 6f 6b 65 74 73 75 2e 4d 44 49 50 61 72 65 6e 74 32 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.MDIParent2.resources
		$a_01_4 = {4b 6f 6b 65 74 73 75 2e 4d 44 49 50 61 72 65 6e 74 33 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.MDIParent3.resources
		$a_01_5 = {4b 6f 6b 65 74 73 75 2e 4d 44 49 50 61 72 65 6e 74 34 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.MDIParent4.resources
		$a_01_6 = {4b 6f 6b 65 74 73 75 2e 4d 44 49 50 61 72 65 6e 74 35 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.MDIParent5.resources
		$a_01_7 = {4b 6f 6b 65 74 73 75 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Koketsu.Properties.Resources.resources
		$a_01_8 = {67 65 74 5f 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 } //1 get_cccccccccccccccccccccccccccccccccccc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_25{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_1 = {43 6f 6d 70 69 6c 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 } //1 CompilerGeneratedAttribute
		$a_01_2 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 EditorBrowsableAttribute
		$a_01_3 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 EditorBrowsableState
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_6 = {42 69 72 64 48 75 6e 74 69 6e 67 47 61 6d 65 2e 46 6f 72 6d 73 2e 47 61 6d 65 4f 70 74 69 6f 6e 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 BirdHuntingGame.Forms.GameOptionsForm.resources
		$a_01_7 = {42 69 72 64 48 75 6e 74 69 6e 67 47 61 6d 65 2e 46 6f 72 6d 73 2e 50 6c 61 79 47 61 6d 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 BirdHuntingGame.Forms.PlayGameForm.resources
		$a_01_8 = {42 69 72 64 48 75 6e 74 69 6e 67 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BirdHuntingGame.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_26{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {34 43 38 31 36 39 35 32 42 41 35 33 43 43 33 36 31 44 38 45 34 35 42 44 38 33 33 33 33 38 44 43 36 34 32 37 45 34 41 35 44 35 46 30 36 45 42 41 44 35 33 35 31 46 44 34 36 34 33 39 41 31 35 41 } //1 4C816952BA53CC361D8E45BD833338DC6427E4A5D5F06EBAD5351FD46439A15A
		$a_01_1 = {41 6c 6b 6f 68 6f 6c 6b 6f 6e 73 75 6d 76 65 72 68 69 6e 64 65 72 75 6e 67 73 6d 61 73 63 68 69 6e 65 6e 2e 47 61 6d 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Alkoholkonsumverhinderungsmaschinen.GameForm.resources
		$a_01_2 = {41 6c 6b 6f 68 6f 6c 6b 6f 6e 73 75 6d 76 65 72 68 69 6e 64 65 72 75 6e 67 73 6d 61 73 63 68 69 6e 65 6e 2e 48 69 67 68 53 63 6f 72 65 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Alkoholkonsumverhinderungsmaschinen.HighScoresForm.resources
		$a_01_3 = {41 6c 6b 6f 68 6f 6c 6b 6f 6e 73 75 6d 76 65 72 68 69 6e 64 65 72 75 6e 67 73 6d 61 73 63 68 69 6e 65 6e 2e 4d 61 69 6e 4d 65 6e 75 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Alkoholkonsumverhinderungsmaschinen.MainMenuForm.resources
		$a_01_4 = {41 6c 6b 6f 68 6f 6c 6b 6f 6e 73 75 6d 76 65 72 68 69 6e 64 65 72 75 6e 67 73 6d 61 73 63 68 69 6e 65 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Alkoholkonsumverhinderungsmaschinen.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_27{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 67 6c 65 54 61 6b 65 6f 75 74 49 6d 61 67 65 44 6f 77 6e 6c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 } //1 GoogleTakeoutImageDownloader.Propertie
		$a_01_1 = {47 6f 6f 67 6c 65 54 61 6b 65 6f 75 74 49 6d 61 67 65 44 6f 77 6e 6c 6f 61 64 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 GoogleTakeoutImageDownloader.Form1.resources
		$a_01_2 = {47 6f 6f 67 6c 65 54 61 6b 65 6f 75 74 49 6d 61 67 65 44 6f 77 6e 6c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GoogleTakeoutImageDownloader.Properties.Resources.resources
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {52 65 61 64 42 79 74 65 } //1 ReadByte
		$a_01_5 = {49 44 6f 77 6e 6c 6f 61 64 50 72 6f 67 72 65 73 73 4e 6f 74 69 66 69 65 72 } //1 IDownloadProgressNotifier
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_7 = {4f 6e 44 6f 77 6e 6c 6f 61 64 46 69 6e 69 73 68 } //1 OnDownloadFinish
		$a_01_8 = {53 74 61 72 74 44 6f 77 6e 6c 6f 61 64 } //1 StartDownload
		$a_01_9 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //1 CreateDirectory
		$a_01_10 = {44 69 72 65 63 74 6f 72 79 49 6e 66 6f } //1 DirectoryInfo
		$a_01_11 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_12 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_28{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_2 = {53 4d 43 2e 55 74 69 6c 69 74 69 65 73 2e 52 53 47 2e 52 61 6e 64 6f 6d } //1 SMC.Utilities.RSG.Random
		$a_01_3 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_4 = {53 4d 43 2e 55 74 69 6c 69 74 69 65 73 2e 52 53 47 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SMC.Utilities.RSG.Properties.Resources.resources
		$a_01_5 = {53 4d 43 2e 55 74 69 6c 69 74 69 65 73 2e 52 53 47 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SMC.Utilities.RSG.Properties
		$a_01_6 = {47 61 6c 53 72 70 79 79 74 6f 59 6f 77 4e 64 5a 42 72 49 5a 41 6c 4f 59 58 6f 67 6e 6d 63 47 65 73 45 67 } //1 GalSrpyytoYowNdZBrIZAlOYXognmcGesEg
		$a_01_7 = {38 34 37 31 36 44 33 38 36 31 38 44 41 43 34 33 32 43 36 37 44 33 39 39 46 41 44 39 46 45 42 38 44 34 35 39 44 36 34 30 36 30 39 43 39 46 35 44 31 35 41 43 42 36 38 36 38 33 33 42 34 46 31 42 } //5 84716D38618DAC432C67D399FAD9FEB8D459D640609C9F5D15ACB686833B4F1B
		$a_03_8 = {06 00 00 06 0b 07 2d f2 02 7b ?? ?? ?? 04 6f ?? ?? ?? 06 00 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*5+(#a_03_8  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_29{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {06 0a 1f 1e 0b 16 0c 2b 0e 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 08 17 58 0c 08 07 32 ee } //1
		$a_01_1 = {4b 56 4c 43 20 6d 65 64 69 61 20 70 6c 61 79 65 72 2c 20 56 69 64 65 6f 4c 41 4e 20 61 6e 64 20 78 32 36 34 20 61 72 65 20 72 65 67 69 73 74 65 72 65 64 20 74 72 61 64 65 6d 61 72 6b 73 20 66 72 6f 6d 20 56 69 64 65 6f 4c 41 4e } //1 KVLC media player, VideoLAN and x264 are registered trademarks from VideoLAN
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp1.Form1.resources
		$a_01_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp1.Properties.Resources.resources
		$a_01_4 = {33 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 54 6f 6f 6c 73 2e 53 74 72 6f 6e 67 6c 79 54 79 70 65 64 52 65 73 6f 75 72 63 65 42 75 69 6c 64 65 72 } //1 3System.Resources.Tools.StronglyTypedResourceBuilder
		$a_01_5 = {73 65 74 5f 4b 65 65 70 41 6c 69 76 65 } //1 set_KeepAlive
		$a_01_6 = {73 65 74 5f 41 6c 6c 6f 77 41 75 74 6f 52 65 64 69 72 65 63 74 } //1 set_AllowAutoRedirect
		$a_01_7 = {73 65 74 5f 55 6e 73 61 66 65 41 75 74 68 65 6e 74 69 63 61 74 65 64 43 6f 6e 6e 65 63 74 69 6f 6e 53 68 61 72 69 6e 67 } //1 set_UnsafeAuthenticatedConnectionSharing
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_30{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {66 61 41 70 69 6e 77 66 64 55 76 79 31 51 6c 46 42 36 41 59 64 6d 35 4d 35 73 59 69 4c 70 77 6e 36 } //1 faApinwfdUvy1QlFB6AYdm5M5sYiLpwn6
		$a_01_1 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.Form1.resources
		$a_01_2 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 69 6e 74 72 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.intro.resources
		$a_01_3 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.MDIParent1.resources
		$a_01_4 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 4d 44 49 50 61 72 65 6e 74 32 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.MDIParent2.resources
		$a_01_5 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.Resources.resources
		$a_01_6 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 70 6c 61 79 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.play.resources
		$a_01_7 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 73 74 61 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.start.resources
		$a_01_8 = {45 73 63 61 70 65 5f 52 6f 6f 6d 5f 47 61 6d 65 2e 75 73 65 72 6c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Escape_Room_Game.userlogin.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_31{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 6c 61 70 70 79 42 69 72 64 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 FlappyBird.Form1.resources
		$a_01_1 = {4c 69 66 65 2e 4c 69 66 65 55 49 2e 72 65 73 6f 75 72 63 65 73 } //1 Life.LifeUI.resources
		$a_01_2 = {48 65 6c 69 63 6f 70 74 65 72 53 68 6f 6f 74 69 6e 67 2e 4d 61 69 6e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 HelicopterShooting.MainGame.resources
		$a_01_3 = {54 72 69 61 6e 67 75 6c 61 74 69 6f 6e 2e 55 49 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Triangulation.UI.MainForm.resources
		$a_01_4 = {48 65 6c 69 63 6f 70 74 65 72 53 68 6f 6f 74 69 6e 67 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 HelicopterShooting.FormMain.resources
		$a_01_5 = {54 72 69 61 6e 67 75 6c 61 74 69 6f 6e 2e 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Triangulation.Core.Properties.Resources.resources
		$a_01_6 = {67 65 74 5f 73 73 73 73 73 } //1 get_sssss
		$a_01_7 = {54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 43 6f 6d 70 61 72 65 72 } //1 TimeZoneInfoComparer
		$a_01_8 = {46 6f 72 6d 31 5f 4c 6f 61 64 00 4c 69 66 65 55 49 5f 4c 6f 61 64 } //1 潆浲弱潌摡䰀晩啥彉潌摡
		$a_00_9 = {73 00 64 00 66 00 73 00 64 00 66 00 73 00 31 00 31 00 31 00 } //1 sdfsdfs111
		$a_03_10 = {0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_03_10  & 1)*1) >=11
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_32{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4d 61 74 68 47 65 6e 65 72 61 74 6f 72 2e 47 65 6e 65 72 61 74 6f 72 73 2e 53 69 6d 70 6c 65 45 71 75 61 74 69 6f 6e } //1 MathGenerator.Generators.SimpleEquation
		$a_01_1 = {4d 61 74 68 47 65 6e 65 72 61 74 6f 72 2e 47 65 6e 65 72 61 74 6f 72 73 2e 53 69 6d 70 6c 65 45 71 75 61 74 69 6f 6e 2e 4d 6f 64 65 6c 73 } //1 MathGenerator.Generators.SimpleEquation.Models
		$a_01_2 = {4d 61 74 68 47 65 6e 65 72 61 74 6f 72 2e 4d 6f 64 65 6c 73 } //1 MathGenerator.Models
		$a_01_3 = {4d 61 74 68 47 65 6e 65 72 61 74 6f 72 2e 47 65 6e 65 72 61 74 6f 72 73 2e 4d 6f 64 65 6c 73 } //1 MathGenerator.Generators.Models
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_5 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_6 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_7 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_8 = {4f 76 65 72 77 6f 6c 66 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Overwolf.Form1.resources
		$a_01_9 = {4f 76 65 72 77 6f 6c 66 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Overwolf.Properties.Resources.resources
		$a_01_10 = {42 34 32 2e 65 78 65 } //1 B42.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_33{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 5f 47 61 73 70 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.Form1.resources
		$a_01_1 = {54 68 65 5f 47 61 73 70 2e 53 70 6c 61 73 68 53 63 72 65 65 6e 31 2e 72 65 73 6f 75 72 63 65 73 } //2 The_Gasp.SplashScreen1.resources
		$a_01_2 = {54 68 65 5f 47 61 73 70 2e 46 6f 72 6d 32 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.Form2.resources
		$a_01_3 = {54 68 65 5f 47 61 73 70 2e 46 6f 72 6d 33 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.Form3.resources
		$a_01_4 = {54 68 65 5f 47 61 73 70 2e 46 6f 72 6d 34 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.Form4.resources
		$a_01_5 = {54 68 65 5f 47 61 73 70 2e 61 69 64 65 2e 72 65 73 6f 75 72 63 65 73 } //2 The_Gasp.aide.resources
		$a_01_6 = {54 68 65 5f 47 61 73 70 2e 43 61 72 64 42 61 63 6b 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.CardBackDialog.resources
		$a_01_7 = {54 68 65 5f 47 61 73 70 2e 44 65 61 6c 41 67 61 69 6e 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.DealAgainDialog.resources
		$a_01_8 = {54 68 65 5f 47 61 73 70 2e 4f 70 74 69 6f 6e 73 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.OptionsDialog.resources
		$a_01_9 = {54 68 65 5f 47 61 73 70 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 The_Gasp.Resources.resources
		$a_03_10 = {0a 02 02 fe 06 1d 00 00 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 02 28 ?? ?? ?? 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1) >=12
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_34{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 44 65 73 6b 74 6f 70 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 TelegramDesktop.Form1.resources
		$a_01_1 = {54 65 6c 65 67 72 61 6d 44 65 73 6b 74 6f 70 2e 66 72 6d 43 61 74 65 67 6f 72 69 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TelegramDesktop.frmCategories.resources
		$a_01_2 = {54 65 6c 65 67 72 61 6d 44 65 73 6b 74 6f 70 2e 66 72 6d 48 61 6e 67 6d 61 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 TelegramDesktop.frmHangman.resources
		$a_01_3 = {54 65 6c 65 67 72 61 6d 44 65 73 6b 74 6f 70 2e 66 72 6d 53 74 61 72 74 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 TelegramDesktop.frmStartMenu.resources
		$a_01_4 = {54 65 6c 65 67 72 61 6d 44 65 73 6b 74 6f 70 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TelegramDesktop.Resources.resources
		$a_01_5 = {6d 5f 46 6f 72 6d 31 } //1 m_Form1
		$a_01_6 = {6d 5f 66 72 6d 43 61 74 65 67 6f 72 69 65 73 } //1 m_frmCategories
		$a_01_7 = {6d 5f 66 72 6d 48 61 6e 67 6d 61 6e } //1 m_frmHangman
		$a_01_8 = {6d 5f 66 72 6d 53 74 61 72 74 4d 65 6e 75 } //1 m_frmStartMenu
		$a_01_9 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_01_10 = {6e 75 6d 6f 66 65 6e 65 6d 69 65 73 73 70 61 77 6e 65 64 } //1 numofenemiesspawned
		$a_01_11 = {6e 75 6d 6f 66 65 6e 65 6d 69 65 73 69 6e 72 6f 75 6e 64 } //1 numofenemiesinround
		$a_01_12 = {66 72 6d 48 61 6e 67 6d 61 6e 5f 4c 6f 61 64 } //1 frmHangman_Load
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_35{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_01_1 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
		$a_01_3 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_4 = {58 6d 6c 53 63 68 65 6d 61 4f 62 6a 65 63 74 43 6f 6c 6c 65 63 74 69 6f 6e } //1 XmlSchemaObjectCollection
		$a_01_5 = {58 6d 6c 53 63 68 65 6d 61 50 61 72 74 69 63 6c 65 } //1 XmlSchemaParticle
		$a_01_6 = {58 6d 6c 53 63 68 65 6d 61 53 65 71 75 65 6e 63 65 } //1 XmlSchemaSequence
		$a_01_7 = {58 6d 6c 53 63 68 65 6d 61 53 65 74 } //1 XmlSchemaSet
		$a_01_8 = {58 6d 6c 52 6f 6f 74 41 74 74 72 69 62 75 74 65 } //1 XmlRootAttribute
		$a_01_9 = {53 79 73 74 65 6d 2e 58 6d 6c 2e 53 65 72 69 61 6c 69 7a 61 74 69 6f 6e } //1 System.Xml.Serialization
		$a_01_10 = {73 65 74 5f 53 63 68 65 6d 61 53 65 72 69 61 6c 69 7a 61 74 69 6f 6e 4d 6f 64 65 } //1 set_SchemaSerializationMode
		$a_01_11 = {43 6c 6f 6e 65 } //1 Clone
		$a_01_12 = {57 72 69 74 65 58 6d 6c 53 63 68 65 6d 61 } //1 WriteXmlSchema
		$a_01_13 = {33 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 54 6f 6f 6c 73 2e 53 74 72 6f 6e 67 6c 79 54 79 70 65 64 52 65 73 6f 75 72 63 65 42 75 69 6c 64 65 72 } //1 3System.Resources.Tools.StronglyTypedResourceBuilder
		$a_01_14 = {43 6f 70 79 72 69 67 68 74 } //1 Copyright
		$a_01_15 = {52 61 64 75 20 4d 61 72 74 69 6e 2c 20 32 30 31 37 } //1 Radu Martin, 2017
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_36{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } //1 Microsoft.VisualBasic.ApplicationServices
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 Microsoft.VisualBasic.CompilerServices
		$a_01_3 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_4 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_5 = {67 61 6d 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 game.My.Resources
		$a_01_6 = {67 61 6d 65 2e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 game.Game.resources
		$a_01_7 = {67 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 game.Resources.resources
		$a_01_8 = {67 61 6d 65 2e 4d 61 69 6e 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 game.MainMenu.resources
		$a_01_9 = {67 61 6d 65 2e 49 6e 73 74 72 75 63 74 69 6f 6e 73 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 game.InstructionsMenu.resources
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_03_11 = {0a 2b 00 06 2a 90 0a 4f 00 00 28 ?? ?? ?? 06 72 [0-03] 70 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 [0-03] 0a 0b 07 74 [0-03] 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_03_11  & 1)*1) >=12
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_37{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 57 73 68 53 68 65 6c 6c 32 } //1 IWshShell2
		$a_01_1 = {45 43 46 31 34 42 39 32 44 46 46 30 41 31 31 31 37 45 43 35 44 35 30 31 45 38 38 30 43 34 36 44 46 35 32 38 43 44 46 45 31 45 34 46 46 31 30 44 42 44 43 44 35 34 44 43 41 33 35 39 32 46 45 33 } //1 ECF14B92DFF0A1117EC5D501E880C46DF528CDFE1E4FF10DBDCD54DCA3592FE3
		$a_01_2 = {36 30 35 46 34 36 45 32 42 46 31 36 35 42 37 37 45 41 37 32 33 33 41 33 34 42 43 45 39 43 32 42 37 30 35 31 42 43 39 32 35 34 38 46 35 39 46 42 45 44 31 39 42 36 45 45 31 31 38 43 41 31 36 46 } //1 605F46E2BF165B77EA7233A34BCE9C2B7051BC92548F59FBED19B6EE118CA16F
		$a_01_3 = {61 56 34 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 aV4.Properties.Resources.resources
		$a_01_4 = {68 42 75 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 hBu.Properties.Resources.resources
		$a_01_5 = {45 39 44 42 38 46 34 44 43 45 43 31 31 30 41 41 33 42 45 35 43 44 34 31 38 33 37 36 39 43 32 42 45 30 30 37 45 43 42 43 35 46 37 43 42 45 46 31 34 41 43 31 41 42 33 32 44 37 42 46 39 41 43 32 } //2 E9DB8F4DCEC110AA3BE5CD4183769C2BE007ECBC5F7CBEF14AC1AB32D7BF9AC2
		$a_01_6 = {64 41 74 74 5d 54 4d 75 74 65 } //2 dAtt]TMute
		$a_01_7 = {21 54 68 6e 78 20 70 72 6f 67 72 66 72 20 63 61 6e 6e 6f 79 25 62 65 20 72 75 6e 25 6e 6e 20 44 4f 53 20 72 74 64 65 2e } //2 !Thnx progrfr cannoy%be run%nn DOS rtde.
		$a_01_8 = {53 79 73 74 6a 72 2e 43 6f 6c 6c 65 68 79 69 6f 6e 73 2e 47 6a 73 65 72 69 63 } //2 Systjr.Collehyions.Gjseric
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=4
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_38{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 00 4c 6f 61 64 00 41 73 73 65 6d 62 6c 79 } //1
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 00 4c 6f 61 64 } //1
		$a_01_3 = {50 6f 6f 6c 2e 66 72 6d 4a 61 74 65 6b 6f 73 4e 79 65 72 2e 72 65 73 6f 75 72 63 65 73 } //3 Pool.frmJatekosNyer.resources
		$a_01_4 = {50 6f 6f 6c 2e 66 72 6d 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 Pool.frmMenu.resources
		$a_01_5 = {50 6f 6f 6c 2e 66 72 6d 50 6f 6e 74 6f 6b 2e 72 65 73 6f 75 72 63 65 73 } //1 Pool.frmPontok.resources
		$a_01_6 = {48 65 6c 69 63 6f 70 74 65 72 53 68 6f 6f 74 69 6e 67 2e 4d 61 69 6e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 HelicopterShooting.MainGame.resources
		$a_01_7 = {48 65 6c 69 63 6f 70 74 65 72 53 68 6f 6f 74 69 6e 67 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 HelicopterShooting.FormMain.resources
		$a_01_8 = {48 65 6c 69 63 6f 70 74 65 72 53 68 6f 6f 74 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 HelicopterShooting.Properties.Resources.resources
		$a_01_9 = {53 6e 61 6b 65 47 61 6d 65 57 69 6e 46 6f 72 6d 73 2e 53 6e 61 6b 65 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 SnakeGameWinForms.SnakeGame.resources
		$a_03_10 = {04 a2 25 18 72 ?? ?? ?? 70 a2 25 19 72 ?? ?? ?? 70 a2 25 1a 72 ?? ?? ?? 70 a2 0a 12 00 06 8e 69 18 59 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_39{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_2 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_3 = {44 69 63 65 52 6f 6c 6c 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 DiceRoller.Form1.resources
		$a_01_4 = {44 69 63 65 52 6f 6c 6c 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 DiceRoller.Properties.Resources.resources
		$a_01_5 = {44 69 63 65 52 6f 6c 6c 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 DiceRoller.Properties
		$a_01_6 = {67 65 74 5f 49 6e 63 6c 75 64 65 50 72 6f 70 65 72 74 69 65 73 } //1 get_IncludeProperties
		$a_01_7 = {73 65 74 5f 49 6e 63 6c 75 64 65 50 72 6f 70 65 72 74 69 65 73 } //1 set_IncludeProperties
		$a_01_8 = {67 65 74 5f 43 61 6e 41 63 63 65 73 73 4d 69 73 73 69 6e 67 50 72 6f 70 65 72 74 69 65 73 } //1 get_CanAccessMissingProperties
		$a_01_9 = {73 65 74 5f 43 61 6e 41 63 63 65 73 73 4d 69 73 73 69 6e 67 50 72 6f 70 65 72 74 69 65 73 } //1 set_CanAccessMissingProperties
		$a_01_10 = {67 65 74 5f 43 61 6e 41 6c 74 65 72 50 72 6f 70 65 72 74 69 65 73 } //1 get_CanAlterProperties
		$a_01_11 = {73 65 74 5f 43 61 6e 41 6c 74 65 72 50 72 6f 70 65 72 74 69 65 73 } //1 set_CanAlterProperties
		$a_03_12 = {0b 2b 00 07 2a 90 0a 4f 00 00 28 ?? ?? ?? 06 72 ?? ?? ?? 70 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 0a 06 74 ?? ?? ?? 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_03_12  & 1)*1) >=13
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_40{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 44 61 74 61 62 61 73 65 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.Database.resources
		$a_01_1 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 61 64 64 75 73 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.adduser.resources
		$a_01_2 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 61 64 64 70 72 6f 64 75 63 74 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.addproduct.resources
		$a_01_3 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 62 69 6c 6c 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.billing.resources
		$a_01_4 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.Login.resources
		$a_01_5 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 53 70 6c 61 73 68 73 63 72 65 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.Splashscreen.resources
		$a_01_6 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 6d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.main.resources
		$a_01_7 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.Resources.resources
		$a_01_8 = {62 65 65 72 70 61 72 6c 6f 75 72 62 69 6c 6c 69 6e 67 73 79 73 74 65 6d 2e 72 65 63 65 69 70 74 2e 72 65 73 6f 75 72 63 65 73 } //1 beerparlourbillingsystem.receipt.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_41{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 44 65 6c 65 74 65 55 73 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmDeleteUser.resources
		$a_01_1 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.Resources.resources
		$a_01_2 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 4d 6f 74 6f 72 45 64 69 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmMotorEdit.resources
		$a_01_3 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 4e 6f 6e 4d 6f 74 6f 72 45 64 69 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmNonMotorEdit.resources
		$a_01_4 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 46 72 6d 44 61 74 61 4d 61 6e 61 67 65 6d 65 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.FrmDataManagement.resources
		$a_01_5 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 4d 6f 74 6f 72 52 65 70 6f 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmMotorReport.resources
		$a_01_6 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 4e 6f 6e 4d 6f 74 6f 72 52 65 70 6f 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmNonMotorReport.resources
		$a_01_7 = {53 63 61 6c 65 5f 44 65 74 65 63 74 2e 66 72 6d 41 62 6f 75 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Scale_Detect.frmAbout.resources
		$a_00_8 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 43 00 68 00 61 00 6e 00 67 00 65 00 64 00 } //1 Password has been succesfully Changed
		$a_03_9 = {de 02 00 dc 00 28 ?? ?? ?? 06 02 6f ?? ?? ?? 0a 00 2a 90 0a 2f 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_03_9  & 1)*1) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_42{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0f 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_1 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 GeneratedCodeAttribute
		$a_01_2 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //1 System.CodeDom.Compiler
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 53 65 74 74 69 6e 67 73 42 61 73 65 } //1 ApplicationSettingsBase
		$a_01_4 = {53 79 73 74 65 6d 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 System.Configuration
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {52 65 61 64 42 79 74 65 } //1 ReadByte
		$a_01_8 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_01_9 = {53 79 6e 63 68 72 6f 6e 69 7a 65 64 } //1 Synchronized
		$a_01_10 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_11 = {33 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 54 6f 6f 6c 73 2e 53 74 72 6f 6e 67 6c 79 54 79 70 65 64 52 65 73 6f 75 72 63 65 42 75 69 6c 64 65 72 } //1 3System.Resources.Tools.StronglyTypedResourceBuilder
		$a_80_12 = {57 65 72 62 65 61 67 65 6e 74 75 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Werbeagentur.Properties.Resources.resources  5
		$a_80_13 = {67 69 6e 5f 72 75 6d 6d 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //gin_rummy.Properties.Resources.resources  5
		$a_80_14 = {4d 61 7a 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Maze.Properties.Resources.resources  5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_80_12  & 1)*5+(#a_80_13  & 1)*5+(#a_80_14  & 1)*5) >=17
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_43{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 6c 65 61 6e 43 68 65 73 73 42 6f 61 72 64 50 69 65 63 65 73 } //1 CleanChessBoardPieces
		$a_01_1 = {47 65 6e 65 72 61 74 65 43 68 65 73 73 50 69 65 63 65 73 } //1 GenerateChessPieces
		$a_01_2 = {63 68 65 73 73 50 69 65 63 65 73 } //1 chessPieces
		$a_01_3 = {50 72 69 6e 74 50 69 65 63 65 73 } //1 PrintPieces
		$a_01_4 = {70 69 65 63 65 73 } //1 pieces
		$a_01_5 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_6 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_7 = {50 72 69 6e 74 47 61 6d 65 52 65 66 65 72 65 6e 63 65 73 } //1 PrintGameReferences
		$a_01_8 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_9 = {53 4d 43 2e 55 74 69 6c 69 74 69 65 73 2e 52 53 47 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SMC.Utilities.RSG.Properties.Resources.resources
		$a_01_10 = {53 4d 43 2e 55 74 69 6c 69 74 69 65 73 2e 52 53 47 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SMC.Utilities.RSG.Properties
		$a_01_11 = {73 65 74 52 61 6e 64 6f 6d 4c 6f 63 61 74 69 6f 6e } //1 setRandomLocation
		$a_01_12 = {44 75 70 6c 69 63 61 74 65 47 6c 6f 62 61 6c 43 6f 6e 74 72 6f 6c 42 6c 6f 63 6b 45 78 63 65 70 74 69 6f 6e } //1 DuplicateGlobalControlBlockException
		$a_01_13 = {41 20 6c 69 62 72 61 72 79 20 66 72 6f 6d 20 67 65 6e 65 72 61 74 69 6e 67 20 72 61 6e 64 6f 6d 20 73 74 72 69 6e 67 73 20 62 61 73 65 64 20 6f 6e 20 61 20 73 69 6d 70 6c 65 20 70 61 74 74 65 72 6e 20 6c 61 6e 67 75 61 67 65 2e } //1 A library from generating random strings based on a simple pattern language.
		$a_01_14 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_15 = {55 70 64 61 74 65 43 68 65 73 73 50 69 65 63 65 4c 6f 63 61 74 69 6f 6e } //1 UpdateChessPieceLocation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_44{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 "
		
	strings :
		$a_00_0 = {49 00 6d 00 61 00 67 00 69 00 6e 00 65 00 72 00 2e 00 6d 00 61 00 6c 00 68 00 65 00 75 00 72 00 65 00 75 00 78 00 } //1 Imaginer.malheureux
		$a_01_1 = {43 61 72 50 61 72 6b 69 6e 67 2e 43 61 72 44 65 74 61 69 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.CarDetails.resources
		$a_01_2 = {43 61 72 50 61 72 6b 69 6e 67 2e 66 72 6d 43 61 72 49 6e 76 65 6e 74 6f 72 79 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.frmCarInventory.resources
		$a_01_3 = {43 61 72 50 61 72 6b 69 6e 67 2e 4c 6f 61 64 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.Load.resources
		$a_01_4 = {43 61 72 50 61 72 6b 69 6e 67 2e 4d 61 69 6e 53 79 73 74 65 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.MainSystem.resources
		$a_01_5 = {43 61 72 50 61 72 6b 69 6e 67 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.Resources.resources
		$a_01_6 = {43 61 72 50 61 72 6b 69 6e 67 2e 50 61 72 6b 69 6e 67 53 6c 6f 74 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.ParkingSlots.resources
		$a_01_7 = {43 61 72 50 61 72 6b 69 6e 67 2e 53 65 72 76 69 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.Services.resources
		$a_01_8 = {43 61 72 50 61 72 6b 69 6e 67 2e 53 69 67 6e 5f 55 70 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.Sign_Up.resources
		$a_01_9 = {43 61 72 50 61 72 6b 69 6e 67 2e 56 69 65 77 4f 70 65 72 61 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.ViewOperations.resources
		$a_01_10 = {43 61 72 50 61 72 6b 69 6e 67 2e 56 69 65 77 56 65 68 69 63 65 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CarParking.ViewVehicels.resources
		$a_01_11 = {46 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 F.g.resources
		$a_00_12 = {41 00 4c 00 4c 00 20 00 56 00 45 00 48 00 49 00 43 00 4c 00 45 00 53 00 20 00 41 00 52 00 45 00 20 00 50 00 41 00 52 00 4b 00 45 00 44 00 20 00 41 00 54 00 20 00 4f 00 57 00 4e 00 45 00 52 00 53 00 20 00 52 00 49 00 53 00 4b 00 21 00 21 00 21 00 } //1 ALL VEHICLES ARE PARKED AT OWNERS RISK!!!
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_00_12  & 1)*1) >=12
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_45{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0f 00 00 "
		
	strings :
		$a_01_0 = {72 62 41 64 6d 69 6e 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 5f 31 } //1 rbAdmin_CheckedChanged_1
		$a_01_1 = {72 62 44 6f 63 74 6f 72 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 5f 31 } //1 rbDoctor_CheckedChanged_1
		$a_01_2 = {72 62 52 65 63 65 70 74 69 6f 6e 69 73 74 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 5f 31 } //1 rbReceptionist_CheckedChanged_1
		$a_01_3 = {72 65 6d 6f 76 65 5f 50 61 74 69 65 6e 74 52 6f 77 43 68 61 6e 67 65 64 } //1 remove_PatientRowChanged
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 43 6f 6d 70 61 72 65 72 } //1 TimeZoneInfoComparer
		$a_01_6 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 SWE2_Project1.Login.resources
		$a_01_7 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 41 64 6d 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 SWE2_Project1.Admin.resources
		$a_01_8 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 44 6f 63 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //1 SWE2_Project1.Doctor.resources
		$a_01_9 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SWE2_Project1.Properties.Resources.resources
		$a_01_10 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 52 65 63 65 70 74 69 6f 6e 69 73 74 2e 72 65 73 6f 75 72 63 65 73 } //1 SWE2_Project1.Receptionist.resources
		$a_01_11 = {53 57 45 32 5f 50 72 6f 6a 65 63 74 31 2e 44 42 44 61 74 61 53 65 74 54 61 62 6c 65 41 64 61 70 74 65 72 73 } //1 SWE2_Project1.DBDataSetTableAdapters
		$a_02_12 = {53 00 57 00 45 00 32 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 [0-05] 73 00 73 00 73 00 73 00 73 00 } //1
		$a_01_13 = {67 65 74 5f 73 73 73 73 } //1 get_ssss
		$a_03_14 = {00 52 65 6d 6f 76 65 00 [0-0f] 2e 65 78 65 00 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_02_12  & 1)*1+(#a_01_13  & 1)*1+(#a_03_14  & 1)*1) >=13
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_46{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 44 69 61 6c 6f 67 31 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.Dialog1.resources
		$a_01_1 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 46 72 6d 56 69 65 77 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.FrmViewer.resources
		$a_01_2 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 4c 61 75 6e 63 68 42 61 72 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.LaunchBar.resources
		$a_01_3 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 4c 6f 61 64 49 6d 61 67 65 46 6f 6c 64 65 72 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.LoadImageFolderDialog.resources
		$a_01_4 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 4d 61 69 6e 5f 53 63 72 65 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.Main_Screen.resources
		$a_01_5 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.Resources.resources
		$a_01_6 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 53 65 74 53 70 65 65 64 44 69 61 6c 6f 67 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.SetSpeedDialog.resources
		$a_01_7 = {54 69 6d 65 53 74 61 6d 70 5f 50 72 65 66 69 78 65 72 2e 54 68 72 65 61 64 43 6f 6e 74 72 6f 6c 6c 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 TimeStamp_Prefixer.ThreadController.resources
		$a_01_8 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //1 get_StartupPath
		$a_01_9 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //1 add_Shutdown
		$a_01_10 = {44 65 6c 65 74 65 44 69 72 65 63 74 6f 72 79 } //1 DeleteDirectory
		$a_01_11 = {52 75 6e 57 6f 72 6b 65 72 41 73 79 6e 63 } //1 RunWorkerAsync
		$a_01_12 = {72 65 6d 6f 76 65 5f 52 75 6e 57 6f 72 6b 65 72 43 6f 6d 70 6c 65 74 65 64 } //1 remove_RunWorkerCompleted
		$a_01_13 = {61 64 64 5f 44 6f 57 6f 72 6b } //1 add_DoWork
		$a_01_14 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //1 get_KeyCode
		$a_01_15 = {00 52 65 6d 6f 76 65 41 74 00 67 65 74 5f 49 6e 76 6f 6b 65 52 65 71 75 69 72 65 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_47{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 5f 46 6c 6f 6f 72 5f 41 72 65 61 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frm_Floor_Area.resources
		$a_01_1 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 46 6f 72 6d 33 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.Form3.resources
		$a_01_2 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 6c 62 6c 66 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.lblform.resources
		$a_01_3 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 5f 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frm_Main.resources
		$a_01_4 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.Resources.resources
		$a_01_5 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 50 61 69 6e 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.Painter.resources
		$a_01_6 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 5f 50 61 69 6e 74 5f 52 65 71 75 69 72 65 6d 65 6e 74 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frm_Paint_Requirements.resources
		$a_01_7 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 50 72 65 73 65 6e 74 61 63 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frmPresentacion.resources
		$a_01_8 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 50 72 69 6e 63 69 70 61 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frmPrincipal.resources
		$a_01_9 = {52 6f 6f 6d 5f 50 61 69 6e 74 65 72 2e 66 72 6d 5f 52 6f 6f 6d 5f 56 6f 6c 75 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 Room_Painter.frm_Room_Volume.resources
		$a_01_10 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 00 54 00 49 6e 73 74 61 6e 63 65 00 44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1
		$a_01_11 = {43 68 72 57 00 43 6f 6e 76 65 72 73 69 6f 6e 73 00 47 65 74 44 6f 6d 61 69 6e 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1
		$a_01_12 = {54 6f 49 6e 74 65 67 65 72 00 73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 潔湉整敧r敳彴慐獳潷摲桃牡
		$a_01_13 = {63 68 6b 52 65 6c 6c 65 6e 61 72 46 69 67 75 72 61 } //1 chkRellenarFigura
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_48{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 Microsoft.VisualBasic.CompilerServices
		$a_01_2 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_3 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_4 = {4d 69 6e 69 47 61 6d 65 43 53 68 61 72 70 2e 50 6c 61 79 69 6e 67 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 MiniGameCSharp.PlayingGame.resources
		$a_01_5 = {4d 69 6e 69 47 61 6d 65 43 53 68 61 72 70 2e 48 69 67 68 53 63 6f 72 65 2e 72 65 73 6f 75 72 63 65 73 } //1 MiniGameCSharp.HighScore.resources
		$a_01_6 = {4d 69 6e 69 47 61 6d 65 43 53 68 61 72 70 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 MiniGameCSharp.frmMain.resources
		$a_01_7 = {4d 69 6e 69 47 61 6d 65 43 53 68 61 72 70 2e 49 6e 73 74 72 75 63 74 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 MiniGameCSharp.Instruction.resources
		$a_01_8 = {4f 6e 65 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 OneGame.Properties.Resources.resources
		$a_01_9 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_03_10 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 43 6c 69 65 6e 74 5c 54 65 6d 70 5c [0-0f] 5c 73 72 63 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c [0-1f] 2e 70 64 62 } //1
		$a_00_11 = {50 00 6c 00 61 00 79 00 74 00 6f 00 6d 00 69 00 63 00 20 00 58 00 61 00 6d 00 61 00 72 00 69 00 6e 00 20 00 2f 00 20 00 4d 00 6f 00 6e 00 6f 00 2e 00 4e 00 45 00 54 00 20 00 2f 00 20 00 43 00 23 00 20 00 74 00 65 00 73 00 74 00 73 00 } //1 Playtomic Xamarin / Mono.NET / C# tests
		$a_00_12 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 73 00 74 00 2e 00 31 00 67 00 2e 00 69 00 6f 00 3a 00 33 00 30 00 30 00 30 00 } //1 http://test.1g.io:3000
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_49{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {37 39 41 38 30 38 42 41 34 44 46 44 35 46 38 42 42 35 38 38 37 42 36 37 41 38 41 31 46 43 30 43 44 30 30 38 43 33 30 33 35 39 39 37 31 37 36 36 38 41 35 32 43 41 37 37 35 36 36 46 42 39 46 35 } //1 79A808BA4DFD5F8BB5887B67A8A1FC0CD008C303599717668A52CA77566FB9F5
		$a_01_1 = {37 42 44 33 30 45 38 46 41 45 31 32 35 34 30 46 45 31 31 45 46 44 44 45 39 34 30 39 45 31 45 42 31 30 33 38 38 46 32 37 37 30 38 38 31 35 44 30 34 43 33 41 34 39 31 31 46 42 38 31 42 41 30 38 } //1 7BD30E8FAE12540FE11EFDDE9409E1EB10388F27708815D04C3A4911FB81BA08
		$a_01_2 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 41 64 6d 69 6e 4d 61 6e 61 67 65 72 2e 46 6f 72 6d 41 64 6d 69 6e 4d 61 6e 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.AdminManager.FormAdminManage.resources
		$a_01_3 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 41 64 6d 69 6e 4d 61 6e 61 67 65 72 2e 46 6f 72 6d 4d 6f 64 69 66 79 50 77 64 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.AdminManager.FormModifyPwd.resources
		$a_01_4 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 46 6f 72 6d 4c 6f 67 51 75 65 72 79 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.FormLogQuery.resources
		$a_01_5 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 64 75 63 74 2e 46 6f 72 6d 49 6e 76 65 72 74 6f 72 79 4d 61 6e 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.Product.FormInvertoryManage.resources
		$a_01_6 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 64 75 63 74 2e 46 6f 72 6d 50 72 6f 64 75 63 74 4d 61 6e 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.Product.FormProductManage.resources
		$a_01_7 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 64 75 63 74 2e 46 6f 72 6d 50 72 6f 64 75 63 74 53 74 6f 72 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.Product.FormProductStorage.resources
		$a_01_8 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 64 75 63 74 2e 46 6f 72 6d 53 61 6c 65 53 74 61 74 69 73 74 69 63 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.Product.FormSaleStatistics.resources
		$a_01_9 = {53 4d 61 72 74 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SMartStorageManager.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_50{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_1 = {4b 61 72 6e 61 2e 57 69 6e 64 6f 77 73 2e 55 49 2e 44 65 73 69 67 6e } //1 Karna.Windows.UI.Design
		$a_01_2 = {31 30 42 35 43 42 41 41 36 33 37 35 41 38 37 44 42 38 45 38 34 42 32 46 33 44 44 41 45 43 32 32 43 45 35 32 30 38 43 31 33 42 36 35 42 35 32 41 46 35 39 37 43 45 30 45 42 46 38 39 34 39 33 36 } //1 10B5CBAA6375A87DB8E84B2F3DDAEC22CE5208C13B65B52AF597CE0EBF894936
		$a_01_3 = {31 32 43 39 45 33 45 31 33 30 43 36 41 38 34 36 39 30 45 33 41 45 46 35 42 42 44 32 37 41 46 37 39 30 30 46 42 45 43 42 34 30 37 35 35 36 30 42 44 35 34 42 32 30 43 39 33 34 33 45 37 46 30 42 } //1 12C9E3E130C6A84690E3AEF5BBD27AF7900FBECB4075560BD54B20C9343E7F0B
		$a_01_4 = {33 42 30 45 34 38 34 32 42 32 38 44 36 42 33 39 45 43 37 32 35 41 36 34 35 39 46 42 39 34 33 46 35 46 31 44 36 35 38 46 34 44 30 45 45 39 39 31 30 30 34 44 44 35 30 46 32 43 31 38 32 46 33 31 } //1 3B0E4842B28D6B39EC725A6459FB943F5F1D658F4D0EE991004DD50F2C182F31
		$a_01_5 = {37 31 38 35 38 38 38 32 38 42 30 34 32 38 44 38 31 38 43 36 45 43 44 46 44 42 33 44 39 30 39 37 37 35 34 31 46 37 41 34 42 41 35 46 36 44 35 36 34 43 33 38 35 45 33 43 36 33 42 41 30 44 38 36 } //1 718588828B0428D818C6ECDFDB3D90977541F7A4BA5F6D564C385E3C63BA0D86
		$a_01_6 = {39 33 45 33 31 38 30 42 44 42 41 45 41 38 37 36 44 31 44 44 44 45 46 41 36 37 35 30 45 32 42 42 33 37 46 41 31 30 42 34 46 31 31 30 33 32 34 35 35 33 43 32 30 41 32 32 36 32 41 44 31 46 33 41 } //1 93E3180BDBAEA876D1DDDEFA6750E2BB37FA10B4F110324553C20A2262AD1F3A
		$a_01_7 = {41 45 39 42 33 36 38 32 31 36 39 41 33 36 37 35 34 33 32 43 43 46 36 37 33 33 30 30 36 42 41 38 38 37 31 43 37 44 34 41 42 32 33 32 41 37 30 45 43 36 41 44 35 45 34 35 37 30 31 43 32 44 32 41 } //1 AE9B3682169A3675432CCF6733006BA8871C7D4AB232A70EC6AD5E45701C2D2A
		$a_01_8 = {45 39 41 45 46 37 41 37 36 36 32 31 46 43 45 44 44 44 43 38 44 34 34 30 41 30 35 44 36 42 43 37 30 45 46 44 31 30 31 43 31 41 36 39 44 41 41 31 31 43 30 33 41 44 42 33 36 43 38 35 46 43 30 43 } //1 E9AEF7A76621FCEDDDC8D440A05D6BC70EFD101C1A69DAA11C03ADB36C85FC0C
		$a_01_9 = {73 65 74 5f 4d 79 50 72 6f 70 65 72 74 79 00 4d 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 69 6f } //1
		$a_01_10 = {73 65 74 5f 50 61 73 73 77 6f 72 64 00 55 73 65 72 6e 61 6d 65 00 50 61 73 73 77 6f 72 64 00 52 65 73 6f 75 72 63 65 73 00 73 69 6d 73 69 6d 2e 50 72 6f 70 65 72 74 69 65 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_51{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 16 00 00 "
		
	strings :
		$a_01_0 = {21 57 68 69 76 20 70 75 6f 67 75 61 6d 23 63 61 71 6e 6f 77 20 62 68 20 72 78 6e 20 6c 6e 20 47 4f 53 23 6d 6f 67 65 2e } //20 !Whiv puoguam#caqnow bh rxn ln GOS#moge.
		$a_01_1 = {54 68 69 73 20 70 7d 6f 67 72 61 6d 20 6e 61 6e 6e 6f 74 20 6d 65 20 72 75 6e 20 74 6e 20 44 4f 53 20 78 6f 64 65 2e } //20 This p}ogram nannot me run tn DOS xode.
		$a_01_2 = {29 54 68 69 73 20 70 7a 77 6f 7a 69 75 20 63 61 6e 6e 6f 7c 28 6a 6d 28 7a 75 6e 20 69 6e 20 4c 57 5b 28 75 77 64 65 2e } //20 )This pzwoziu canno|(jm(zun in LW[(uwde.
		$a_01_3 = {21 54 68 69 79 26 76 72 6f 67 72 61 6d 26 69 67 6e 6e 6f 74 20 62 6b 26 78 75 6e 20 69 6e 20 4a 55 59 20 6d 6f 64 65 2e } //20 !Thiy&vrogram&ignnot bk&xun in JUY mode.
		$a_01_4 = {31 64 78 69 73 20 70 72 6f 67 72 71 7d 30 63 61 6e 6e 6f 74 20 62 75 30 } //20 1dxis progrq}0cannot bu0
		$a_01_5 = {72 6f 67 72 61 6d 37 7a 78 6e 6e 6f 74 20 62 7c 37 } //20 rogram7zxnnot b|7
		$a_01_6 = {75 6e 20 69 6e 20 5b 66 6a 20 6d 6f 64 65 } //1 un in [fj mode
		$a_01_7 = {75 6e 20 69 6e 20 44 4f 63 30 7d 6f 64 65 2e } //1 un in DOc0}ode.
		$a_01_8 = {2e 4e 55 64 56 72 61 6d 65 77 6f 72 6b 3c 66 75 72 73 69 6f 6e 3d 76 34 3e 45 } //1 .NUdVramework<fursion=v4>E
		$a_01_9 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_10 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6e 73 74 72 61 69 6e 65 64 45 78 65 63 75 74 69 6f 6e } //1 System.Runtime.ConstrainedExecution
		$a_01_11 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 53 65 72 69 61 6c 69 7a 61 74 69 6f 6e } //1 System.Runtime.Serialization
		$a_01_12 = {23 42 72 6f 6a } //1 #Broj
		$a_01_13 = {53 79 73 7a 6b 73 2e 57 69 6e 64 6f 7d 79 34 46 6f 72 6d 73 } //1 Syszks.Windo}y4Forms
		$a_01_14 = {6b 6b 78 74 65 6c 33 32 2e 64 72 72 } //1 kkxtel32.drr
		$a_01_15 = {2e 72 73 72 6b } //1 .rsrk
		$a_01_16 = {73 74 65 6d 38 5c 65 73 6f 75 7c 6d 65 73 2e 52 6f 7d 6f 75 72 63 6f 5c 65 61 64 65 7c 36 20 6d 73 63 79 7c 6c 69 62 } //20 stem8\esou|mes.Ro}ourco\eade|6 mscy|lib
		$a_01_17 = {54 6f 6b 65 78 47 62 37 37 61 3f 6d 35 36 31 39 3d 3e 65 30 38 39 2d 5d 79 73 74 65 77 38 52 65 73 6f } //20 TokexGb77a?m5619=>e089-]ystew8Reso
		$a_01_18 = {75 6e 20 69 6e 20 5b 66 6a 20 6d 6f 64 65 2e 24 24 21 24 } //1 un in [fj mode.$$!$
		$a_01_19 = {50 75 73 7d 69 63 4b 65 79 54 6f 7c 76 6e } //1 Pus}icKeyTo|vn
		$a_01_20 = {65 6d 2e 43 6f 6c 6c 76 74 74 69 6f 6e 73 2e 47 76 } //1 em.Collvttions.Gv
		$a_01_21 = {31 70 72 6f 67 72 61 6d 31 74 61 6e 6e 6f 74 20 62 76 31 72 75 6e 20 69 6e 20 55 } //20 1program1tannot bv1run in U
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*20+(#a_01_17  & 1)*20+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*20) >=22
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_52{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 62 72 69 63 6b 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Databricks.Properties.Resources.resources
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {4c 6f 61 64 4b 6e 6f 77 6e 54 79 70 65 57 69 74 68 6f 75 74 56 65 72 73 69 6f 6e 43 68 65 63 6b } //1 LoadKnownTypeWithoutVersionCheck
		$a_01_3 = {45 6e 67 69 6e 65 50 61 74 68 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 4e 61 6d 65 } //1 EnginePathEnvironmentVariableName
		$a_01_4 = {47 65 74 46 61 6c 6c 62 61 63 6b 45 6e 67 69 6e 65 53 6f 75 72 63 65 43 6f 64 65 44 69 72 65 63 74 6f 72 79 } //1 GetFallbackEngineSourceCodeDirectory
		$a_01_5 = {47 65 74 44 61 74 61 62 72 69 63 6b 73 53 6f 6c 75 74 69 6f 6e 46 69 6c 65 50 61 74 68 } //1 GetDatabricksSolutionFilePath
		$a_01_6 = {47 65 74 45 78 65 63 75 74 61 62 6c 65 44 69 72 65 63 74 6f 72 79 } //1 GetExecutableDirectory
		$a_01_7 = {49 73 44 61 74 61 62 72 69 63 6b 73 50 61 74 68 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 41 76 61 69 6c 61 62 6c 65 } //1 IsDatabricksPathEnvironmentVariableAvailable
		$a_01_8 = {47 65 74 44 61 74 61 62 72 69 63 6b 73 49 6e 73 74 61 6c 6c 65 64 44 69 72 65 63 74 6f 72 79 } //1 GetDatabricksInstalledDirectory
		$a_01_9 = {63 6f 70 79 54 6f 4c 6f 63 61 6c 46 6f 6c 64 65 72 46 6f 72 45 78 65 63 75 74 69 6f 6e } //1 copyToLocalFolderForExecution
		$a_01_10 = {54 72 79 54 6f 43 6f 70 79 44 65 70 65 6e 64 65 6e 63 79 46 69 6c 65 } //1 TryToCopyDependencyFile
		$a_01_11 = {52 75 6e 42 61 73 65 4d 65 74 68 6f 64 57 69 74 68 41 74 74 72 69 62 75 74 65 } //1 RunBaseMethodWithAttribute
		$a_01_12 = {52 75 6e 54 68 69 73 43 6c 61 73 73 4d 65 74 68 6f 64 57 69 74 68 41 74 74 72 69 62 75 74 65 } //1 RunThisClassMethodWithAttribute
		$a_01_13 = {53 74 61 72 74 65 64 46 72 6f 6d 4e 43 72 75 6e 63 68 } //1 StartedFromNCrunch
		$a_01_14 = {53 74 61 72 74 65 64 46 72 6f 6d 50 72 6f 67 72 61 6d 4d 61 69 6e } //1 StartedFromProgramMain
		$a_01_15 = {43 6f 6e 76 65 72 74 46 69 72 73 74 43 68 61 72 61 63 74 65 72 54 6f 55 70 70 65 72 43 61 73 65 } //1 ConvertFirstCharacterToUpperCase
		$a_01_16 = {43 6f 6e 74 65 6e 74 4c 6f 61 64 65 72 41 6c 72 65 61 64 79 45 78 69 73 74 73 49 74 49 73 4f 6e 6c 79 41 6c 6c 6f 77 65 64 54 6f 53 65 74 42 65 66 6f 72 65 54 68 65 41 70 70 53 74 61 72 74 73 } //1 ContentLoaderAlreadyExistsItIsOnlyAllowedToSetBeforeTheAppStarts
		$a_01_17 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_18 = {44 61 74 61 62 72 69 63 6b 73 2e 43 6f 6d 6d 61 6e 64 73 } //1 Databricks.Commands
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=19
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_53{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {4c 4d 53 5f 44 42 5f 50 72 6f 6a 65 63 74 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 LMS_DB_Project.Form1.resources
		$a_01_1 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 43 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.Card.resources
		$a_01_2 = {4c 69 62 72 61 72 79 5f 4d 61 69 6e 2e 44 65 74 61 69 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Library_Main.Detail.resources
		$a_01_3 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 41 64 6d 69 6e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.AdminMain.resources
		$a_01_4 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 42 6f 72 72 6f 77 52 65 74 75 72 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.BorrowReturn.resources
		$a_01_5 = {4c 69 62 72 61 72 79 5f 4d 61 69 6e 2e 4d 65 6d 62 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Library_Main.Member.resources
		$a_01_6 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 52 65 61 64 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.Reader.resources
		$a_01_7 = {4c 69 62 72 61 72 79 5f 4d 61 69 6e 2e 4d 61 6e 61 67 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Library_Main.Manager.resources
		$a_01_8 = {4c 4d 53 5f 44 42 5f 50 72 6f 6a 65 63 74 2e 41 64 64 42 6f 72 72 6f 77 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 LMS_DB_Project.AddBorrower.resources
		$a_01_9 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.Properties.Resources.resources
		$a_01_10 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 73 64 65 66 73 64 66 73 64 66 73 66 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.sdefsdfsdfsfs.resources
		$a_01_11 = {4c 4d 53 5f 44 42 5f 50 72 6f 6a 65 63 74 2e 53 65 61 72 63 68 5f 42 6f 6f 6b 73 2e 72 65 73 6f 75 72 63 65 73 } //1 LMS_DB_Project.Search_Books.resources
		$a_01_12 = {4c 4d 53 5f 44 42 5f 50 72 6f 6a 65 63 74 2e 42 6f 6f 6b 5f 4c 6f 61 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //1 LMS_DB_Project.Book_Loans.resources
		$a_01_13 = {4d 61 69 6e 5f 4c 69 62 72 61 72 79 2e 49 6e 73 65 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Main_Library.Insert.resources
		$a_01_14 = {4c 69 62 72 61 72 79 5f 4d 61 69 6e 2e 4c 69 62 72 61 72 79 2e 72 65 73 6f 75 72 63 65 73 } //1 Library_Main.Library.resources
		$a_00_15 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 2e 00 69 00 6d 00 67 00 75 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 http://i.imgur.com/
		$a_03_16 = {0a 19 9a 0a 06 14 03 6f [0-03] 0a 90 0a 5f 00 00 28 [0-03] 06 6f ?? ?? ?? 06 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 16 9a 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_00_15  & 1)*1+(#a_03_16  & 1)*1) >=17
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_54{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 "
		
	strings :
		$a_01_0 = {30 36 38 37 44 32 41 37 45 42 34 42 41 35 46 32 45 31 45 31 39 33 36 34 44 38 33 35 45 31 36 36 43 38 38 43 45 45 37 38 41 30 44 34 42 35 46 33 35 39 35 30 33 38 46 39 35 35 39 30 45 42 44 36 } //1 0687D2A7EB4BA5F2E1E19364D835E166C88CEE78A0D4B5F3595038F95590EBD6
		$a_01_1 = {41 30 33 41 44 35 42 41 45 37 30 34 35 30 44 42 41 41 39 33 34 41 35 36 44 30 35 33 39 34 33 33 44 37 32 38 37 43 45 32 42 34 37 30 38 32 33 35 39 46 32 43 30 42 42 45 31 45 31 45 43 32 44 39 } //1 A03AD5BAE70450DBAA934A56D0539433D7287CE2B47082359F2C0BBE1E1EC2D9
		$a_01_2 = {41 36 33 42 42 44 42 41 46 34 43 32 33 31 42 39 43 42 37 39 43 44 43 35 44 35 45 31 46 38 31 45 45 41 37 33 38 37 30 34 45 31 39 36 35 43 44 44 37 45 44 32 38 36 39 41 30 33 45 37 35 31 39 36 } //1 A63BBDBAF4C231B9CB79CDC5D5E1F81EEA738704E1965CDD7ED2869A03E75196
		$a_01_3 = {37 31 39 32 33 38 35 43 33 43 30 36 30 35 44 45 35 35 42 42 39 34 37 36 43 45 31 44 39 30 37 34 38 31 39 30 45 43 42 33 32 41 38 45 45 44 37 46 35 32 30 37 42 33 30 43 46 36 41 31 46 45 38 39 } //1 7192385C3C0605DE55BB9476CE1D90748190ECB32A8EED7F5207B30CF6A1FE89
		$a_01_4 = {34 31 45 33 43 38 45 33 39 30 33 36 41 37 37 31 45 33 45 46 33 34 44 43 36 38 43 36 32 41 33 34 41 42 43 38 34 34 35 31 39 37 36 42 42 35 34 30 46 41 39 39 30 35 35 42 39 36 38 42 44 33 41 32 } //1 41E3C8E39036A771E3EF34DC68C62A34ABC84451976BB540FA99055B968BD3A2
		$a_01_5 = {34 30 41 33 33 37 30 46 30 32 33 36 31 37 42 34 37 32 41 44 45 35 36 43 36 45 38 36 30 41 34 41 41 41 45 33 33 31 30 33 44 41 46 45 33 35 41 36 41 36 36 43 43 38 45 35 46 36 45 45 32 45 32 35 } //1 40A3370F023617B472ADE56C6E860A4AAAE33103DAFE35A6A66CC8E5F6EE2E25
		$a_01_6 = {35 46 45 38 42 36 38 38 42 34 42 41 41 37 37 34 44 35 39 32 38 43 39 45 45 33 35 39 30 43 42 34 37 33 30 42 42 36 34 45 41 43 30 44 35 44 35 38 32 42 30 34 43 45 44 34 46 36 46 43 34 32 30 36 } //1 5FE8B688B4BAA774D5928C9EE3590CB4730BB64EAC0D5D582B04CED4F6FC4206
		$a_01_7 = {31 44 44 46 36 44 43 45 44 36 30 33 38 44 41 42 35 42 45 34 38 33 32 37 38 44 41 30 35 30 39 37 46 33 39 32 34 35 46 44 37 37 44 45 34 42 37 43 31 33 45 45 45 33 41 30 44 37 45 31 42 35 36 41 } //1 1DDF6DCED6038DAB5BE483278DA05097F39245FD77DE4B7C13EEE3A0D7E1B56A
		$a_01_8 = {43 68 65 73 73 47 61 6d 65 53 65 6d 65 73 74 72 2e 45 6e 64 47 61 6d 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 ChessGameSemestr.EndGameForm.resources
		$a_01_9 = {57 69 6e 64 6f 77 47 61 6d 65 43 68 65 73 73 2e 50 61 77 6e 55 6e 64 65 72 50 72 6f 6d 6f 74 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowGameChess.PawnUnderPromotion.resources
		$a_01_10 = {57 69 6e 64 6f 77 47 61 6d 65 43 68 65 73 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowGameChess.Properties.Resources.resources
		$a_01_11 = {43 68 65 73 73 47 61 6d 65 53 65 6d 65 73 74 72 2e 43 75 73 74 6f 6d 4d 65 73 73 61 67 65 42 6f 78 2e 72 65 73 6f 75 72 63 65 73 } //1 ChessGameSemestr.CustomMessageBox.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=6
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_55{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_00_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp1.Properties.Resources
		$a_00_1 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 32 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-20001-00001}
		$a_00_2 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 32 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-20001-00002}
		$a_00_3 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 33 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-30001-00001}
		$a_00_4 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 33 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-30001-00002}
		$a_00_5 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-40001-00001}
		$a_00_6 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-40001-00002}
		$a_00_7 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-50001-00001}
		$a_00_8 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-50001-00002}
		$a_00_9 = {47 00 65 00 74 00 44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 46 00 6f 00 72 00 46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 69 00 6e 00 74 00 65 00 72 00 } //1 GetDelegateForFunctionPointer
		$a_00_10 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f 00 } //1 file:///
		$a_01_11 = {57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 } //1
		$a_01_12 = {0b 4f 00 70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00 63 00 65 00 73 00 73 } //1
		$a_01_13 = {48 00 61 00 6e 00 64 00 6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00 6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 Handleༀkernel ഀ32.dll
		$a_01_14 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 20 00 00 0b 41 00 6c 00 6c 00 6f 00 63 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_56{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 43 68 6e 67 65 5f 50 77 64 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.Chnge_Pwd.resources
		$a_01_1 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 4d 61 69 6e 5f 53 63 72 65 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.Main_Screen.resources
		$a_01_2 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 52 65 73 75 6c 74 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.ResultsForm.resources
		$a_01_3 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 53 65 74 5f 4d 61 69 6c 5f 53 65 74 74 69 6e 67 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.Set_Mail_Settings.resources
		$a_01_4 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 53 79 6e 63 68 65 72 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.SyncherForm.resources
		$a_01_5 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 56 61 6c 69 64 61 73 69 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.Validasi.resources
		$a_01_6 = {46 6f 6c 64 65 72 5f 50 72 6f 74 65 63 74 6f 72 2e 57 65 6c 63 6f 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 Folder_Protector.Welcome.resources
		$a_01_7 = {6d 5f 43 68 6e 67 65 5f 50 77 64 } //1 m_Chnge_Pwd
		$a_01_8 = {6d 5f 53 65 74 5f 53 63 68 65 64 75 6c 65 64 5f 54 69 6d 65 } //1 m_Set_Scheduled_Time
		$a_00_9 = {48 00 6b 00 65 00 79 00 5f 00 4c 00 6f 00 63 00 61 00 6c 00 5f 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 42 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 } //1 Hkey_Local_Machine\Software\VB Folder Protect
		$a_00_10 = {43 00 3a 00 5c 00 41 00 70 00 70 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 6c 00 6f 00 67 00 } //1 C:\AppLocker.log
		$a_00_11 = {43 00 3a 00 5c 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //1 C:\Locker Folder
		$a_00_12 = {46 00 6f 00 72 00 63 00 65 00 20 00 42 00 61 00 63 00 6b 00 75 00 70 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Force Backup Operation
		$a_00_13 = {53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 4e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 45 00 6d 00 61 00 69 00 6c 00 } //1 Sending Shutdown Notification Email
		$a_02_14 = {5c 00 41 00 75 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-05] 0b 66 00 6f 00 72 00 63 00 65 00 } //1
		$a_01_15 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 50 72 6f 6a 65 63 74 44 61 74 61 } //1 牃慥整湉瑳湡散倀潲敪瑣慄慴
		$a_01_16 = {52 65 6d 6f 76 65 00 43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 00 49 6e 73 74 61 6e 63 65 00 43 6f 6d 70 6f 6e 65 6e 74 00 44 69 73 70 6f 73 65 00 44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 敒潭敶䌀敲瑡彥䥟獮慴据彥_湉瑳湡散䌀浯潰敮瑮䐀獩潰敳䐀獩潰敳彟湉瑳湡散彟
		$a_03_17 = {67 65 74 5f 53 65 6c 65 63 74 65 64 50 61 74 68 00 53 65 61 72 63 68 00 [0-3f] 00 52 65 6d 6f 76 65 41 63 63 65 73 73 52 75 6c 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_02_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_03_17  & 1)*1) >=18
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_57{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 "
		
	strings :
		$a_01_0 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 41 62 6f 75 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.About.resources
		$a_01_1 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 47 61 6d 65 4f 76 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.GameOver.resources
		$a_01_2 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 48 65 6c 70 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.Help.resources
		$a_01_3 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 43 68 6f 6f 73 65 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.Choose.resources
		$a_01_4 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.MDIParent1.resources
		$a_01_5 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 50 6c 61 79 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.Play.resources
		$a_01_6 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Gadz.Tetris.Desktop.Properties.Resources.resources
		$a_01_7 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 42 41 43 4b 47 52 4f 55 4e 44 5f 54 45 54 52 49 53 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.BACKGROUND_TETRIS.png
		$a_01_8 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 42 47 5f 46 41 44 45 44 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.BG_FADED.png
		$a_01_9 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 62 6c 75 65 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_blue.png
		$a_01_10 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 42 4c 4f 43 4b 5f 43 4c 41 53 53 49 43 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.BLOCK_CLASSIC.png
		$a_01_11 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 42 4c 4f 43 4b 5f 43 4c 41 53 53 49 43 5f 46 41 44 45 44 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.BLOCK_CLASSIC_FADED.png
		$a_01_12 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 63 79 61 6e 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_cyan.png
		$a_01_13 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 67 72 65 65 6e 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_green.png
		$a_01_14 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 6f 72 61 6e 67 65 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_orange.png
		$a_01_15 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 70 75 72 70 6c 65 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_purple.png
		$a_01_16 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 72 65 64 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_red.png
		$a_01_17 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 62 6c 6f 63 6b 5f 79 65 6c 6c 6f 77 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.block_yellow.png
		$a_01_18 = {47 61 64 7a 2e 54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 49 6d 61 67 65 6e 73 2e 47 41 4d 45 5f 4f 56 45 52 5f 4c 41 59 45 52 2e 70 6e 67 } //1 Gadz.Tetris.Desktop.Imagens.GAME_OVER_LAYER.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=19
 
}
rule _#HSTR_MSIL_AgentTesla_AQ_58{
	meta:
		description = "!#HSTR:MSIL/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 1c 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 44 41 4c } //1 Online_Shopping_Management_System.DAL
		$a_01_1 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 42 4c } //1 Online_Shopping_Management_System.BL
		$a_01_2 = {43 61 63 68 65 64 43 72 79 73 74 61 6c 52 65 70 6f 72 74 5f 41 4c 4c 5f 50 52 44 43 54 53 } //1 CachedCrystalReport_ALL_PRDCTS
		$a_01_3 = {43 61 63 68 65 64 43 72 79 73 74 61 6c 52 65 70 6f 72 74 5f 41 6c 6c 5f 43 41 54 } //1 CachedCrystalReport_All_CAT
		$a_01_4 = {43 61 63 68 65 64 43 72 79 73 74 61 6c 52 65 70 6f 72 74 5f 53 4e 47 4c 5f 50 52 44 43 54 } //1 CachedCrystalReport_SNGL_PRDCT
		$a_01_5 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 52 50 52 54 } //1 Online_Shopping_Management_System.RPRT
		$a_01_6 = {43 72 79 73 74 61 6c 44 65 63 69 73 69 6f 6e 73 2e 52 65 70 6f 72 74 53 6f 75 72 63 65 } //1 CrystalDecisions.ReportSource
		$a_01_7 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 53 48 4f 57 5f 50 49 43 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.SHOW_PIC.resources
		$a_01_8 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 52 50 52 54 2e 50 52 4e 54 5f 53 4e 47 4c 5f 50 52 44 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.RPRT.PRNT_SNGL_PRD.resources
		$a_01_9 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 4d 61 69 6e 5f 46 52 4d 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.Main_FRM.resources
		$a_01_10 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 4c 4f 47 49 4e 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_LOGIN.resources
		$a_01_11 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 41 44 44 5f 55 53 45 52 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_ADD_USER.resources
		$a_01_12 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 4f 52 44 45 52 53 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_ORDERS.resources
		$a_01_13 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 56 49 45 57 5f 50 52 4f 44 43 54 53 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_VIEW_PRODCTS.resources
		$a_01_14 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 41 44 44 5f 50 52 4f 44 55 43 54 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_ADD_PRODUCT.resources
		$a_01_15 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 42 45 4c 4c 53 5f 4d 4e 47 4d 4e 54 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_BELLS_MNGMNT.resources
		$a_01_16 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 55 53 45 52 53 5f 4d 4e 47 4d 4e 54 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_USERS_MNGMNT.resources
		$a_01_17 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 43 55 53 54 5f 56 49 45 57 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_CUST_VIEW.resources
		$a_01_18 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 52 65 73 74 6f 72 65 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_Restore.resources
		$a_01_19 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 54 75 72 6e 69 6e 67 5f 52 65 66 75 6e 64 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_Turning_Refunding.resources
		$a_01_20 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 42 61 63 6b 55 70 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_BackUp.resources
		$a_01_21 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 72 6d 5f 4e 55 5f 43 75 73 72 6f 6d 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.Frm_NU_Cusromer.resources
		$a_01_22 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.Properties.Resources.resources
		$a_01_23 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 53 65 74 74 69 6e 67 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_Settings.resources
		$a_01_24 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 43 41 54 5f 4d 6e 67 6d 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_CAT_Mngmnt.resources
		$a_01_25 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 50 72 64 63 74 5f 4d 6e 67 6d 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.Prdct_Mngmnt.resources
		$a_01_26 = {4f 6e 6c 69 6e 65 5f 53 68 6f 70 70 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 4c 2e 46 52 4d 5f 44 65 6c 69 76 65 72 79 5f 42 6f 79 2e 72 65 73 6f 75 72 63 65 73 } //1 Online_Shopping_Management_System.PL.FRM_Delivery_Boy.resources
		$a_03_27 = {0a 06 0b 2b 00 07 2a 90 0a 3f 00 00 28 ?? ?? ?? 06 6f ?? ?? ?? 06 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_03_27  & 1)*1) >=28
 
}