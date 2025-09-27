
void FUN_0800d3dc(int *param_1,uint param_2,undefined4 param_3)

{
  int *piVar1;
  uint extraout_r1;
  uint uVar2;
  int iVar3;
  uint local_1c;
  undefined4 uStack_18;
  
  piVar1 = param_1 + 2;
  *param_1 = (int)piVar1;
  uVar2 = param_2;
  local_1c = param_2;
  uStack_18 = param_3;
  if (param_2 == 0) {
    FUN_080104fc(DAT_0800d42c);
    uVar2 = extraout_r1;
  }
  local_1c = FUN_08005ea0(uVar2);
  iVar3 = param_2 + local_1c;
  if (0xf < local_1c) {
    piVar1 = (int *)FUN_08017ce4(param_1,&local_1c,0);
    *param_1 = (int)piVar1;
    param_1[2] = local_1c;
  }
  FUN_08017df2(piVar1,param_2,iVar3);
  param_1[1] = local_1c;
  *(undefined1 *)(*param_1 + local_1c) = 0;
  return;
}

