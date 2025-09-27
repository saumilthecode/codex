
char * FUN_0801f9f8(undefined4 param_1,int param_2,char *param_3,char *param_4)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  
  pcVar3 = (char *)0x0;
  while( true ) {
    cVar1 = *param_3;
    pcVar2 = param_3;
    if (pcVar3 == param_4) {
      do {
        pcVar4 = pcVar2;
        pcVar2 = pcVar4 + 1;
      } while (*pcVar4 != '\0');
      return pcVar4 + ((int)pcVar3 - (int)param_3);
    }
    pcVar3[param_2] = cVar1;
    if (cVar1 == '\0') break;
    pcVar3 = pcVar3 + 1;
    param_3 = param_3 + 1;
  }
  return pcVar3;
}

