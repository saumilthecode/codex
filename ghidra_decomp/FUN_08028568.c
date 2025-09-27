
void FUN_08028568(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = DAT_08028588;
  *DAT_08028588 = 0;
  iVar2 = FUN_080002a8(param_2,param_3,param_4,param_4,param_4);
  if ((iVar2 == -1) && (*piVar1 != 0)) {
    *param_1 = *piVar1;
  }
  return;
}

