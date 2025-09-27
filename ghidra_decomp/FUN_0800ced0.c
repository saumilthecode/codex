
undefined4 *
FUN_0800ced0(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined1 param_7,undefined4 param_8,int *param_9
            ,int *param_10)

{
  int iVar1;
  int *piVar2;
  int unaff_r9;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 local_60;
  undefined4 local_5c;
  int local_58;
  int *local_54;
  int local_50;
  int local_4c [4];
  undefined1 auStack_3c [24];
  undefined4 local_24;
  
  local_24 = 0;
  local_58 = 0;
  local_60 = param_3;
  local_5c = param_4;
  FUN_08009d48(&local_68,0,*(undefined4 *)(param_2 + 8),param_3,param_4,param_5,param_6,param_7,
               param_8,&local_58,0,auStack_3c);
  local_60 = local_68;
  local_5c = uStack_64;
  if (local_58 == 0) {
    FUN_0800cde0(&local_54,auStack_3c);
    iVar1 = FUN_08017cd8(&local_54);
    if (iVar1 == 0) {
      iVar1 = FUN_08017cd8(param_10);
      piVar2 = (int *)0x0;
      if (iVar1 == 0) {
        piVar2 = (int *)*param_10;
        unaff_r9 = param_10[2];
      }
      *param_10 = (int)local_54;
      param_10[1] = local_50;
      param_10[2] = local_4c[0];
      local_54 = piVar2;
      iVar1 = unaff_r9;
      if (piVar2 == (int *)0x0) {
        local_54 = local_4c;
        iVar1 = local_4c[0];
      }
    }
    else {
      if (local_50 != 0) {
        FUN_08017d6c(*param_10,local_54,local_50);
      }
      param_10[1] = local_50;
      *(undefined1 *)(*param_10 + local_50) = 0;
      iVar1 = local_4c[0];
    }
    local_4c[0] = iVar1;
    local_50 = 0;
    *(undefined1 *)local_54 = 0;
    FUN_08006cec(&local_54);
  }
  else {
    *param_9 = local_58;
  }
  *param_1 = local_60;
  param_1[1] = local_5c;
  FUN_08009636(auStack_3c);
  return param_1;
}

