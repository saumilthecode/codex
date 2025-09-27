
void FUN_080285b4(int *param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = DAT_080285d0;
  *DAT_080285d0 = 0;
  iVar2 = FUN_0800041c(param_2);
  if ((iVar2 == -1) && (*piVar1 != 0)) {
    *param_1 = *piVar1;
  }
  return;
}

