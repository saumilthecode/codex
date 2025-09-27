
void FUN_0800bcd4(int *param_1,uint param_2,uint param_3)

{
  int *piVar1;
  uint local_14;
  
  piVar1 = param_1 + 2;
  *param_1 = (int)piVar1;
  if ((param_2 == 0) && (param_3 != 0)) {
    local_14 = param_2;
    piVar1 = (int *)FUN_080104fc(DAT_0800bd18);
  }
  local_14 = param_3;
  if (0xf < param_3) {
    piVar1 = (int *)FUN_08017ce4(param_1,&local_14,0);
    *param_1 = (int)piVar1;
    param_1[2] = local_14;
  }
  FUN_08017df2(piVar1,param_2,param_2 + param_3);
  param_1[1] = local_14;
  *(undefined1 *)(*param_1 + local_14) = 0;
  return;
}

