
int FUN_08028e9c(undefined4 param_1,char *param_2,int *param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  int *piVar5;
  int *piVar6;
  int iVar7;
  
  piVar2 = DAT_08028f10;
  FUN_0802afa0();
  piVar5 = (int *)*piVar2;
  pcVar4 = param_2;
  if (piVar5 != (int *)0x0) {
    do {
      cVar1 = *pcVar4;
      if (cVar1 == '\0') {
        iVar7 = (int)pcVar4 - (int)param_2;
        while( true ) {
          piVar6 = piVar5;
          if (*piVar6 == 0) break;
          iVar3 = FUN_08026936(*piVar6,param_2,iVar7);
          piVar5 = piVar6 + 1;
          if ((iVar3 == 0) && (iVar3 = *piVar6, *(char *)(iVar3 + iVar7) == '=')) {
            *param_3 = (int)piVar6 - *piVar2 >> 2;
            FUN_0802afac(param_1);
            return iVar3 + iVar7 + 1;
          }
        }
        break;
      }
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '=');
  }
  FUN_0802afac(param_1);
  return 0;
}

