
void FUN_08017ede(int *param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  
  iVar3 = param_1[1];
  uVar4 = param_2;
  uVar1 = FUN_08017e26();
  uVar2 = iVar3 + 1;
  if (uVar1 < uVar2) {
    FUN_08017e38(param_1,iVar3,0,0,1,uVar4,param_3);
  }
  *(char *)(*param_1 + iVar3) = (char)param_2;
  param_1[1] = uVar2;
  *(undefined1 *)(*param_1 + uVar2) = 0;
  return;
}

