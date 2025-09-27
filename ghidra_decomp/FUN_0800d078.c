
undefined4 *
FUN_0800d078(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined1 param_7,undefined4 param_8,int *param_9
            ,undefined4 *param_10)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 unaff_r9;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 local_60;
  undefined4 local_5c;
  int local_58;
  undefined4 *local_54;
  int local_50;
  undefined4 local_4c [4];
  undefined1 auStack_3c [24];
  undefined4 local_24;
  
  local_24 = 0;
  local_58 = 0;
  local_60 = param_3;
  local_5c = param_4;
  FUN_08009de0(&local_68,0,*(undefined4 *)(param_2 + 8),param_3,param_4,param_5,param_6,param_7,
               param_8,&local_58,0,auStack_3c);
  local_60 = local_68;
  local_5c = uStack_64;
  if (local_58 == 0) {
    FUN_0800cfb0(&local_54,auStack_3c);
    iVar2 = FUN_0801e984(&local_54);
    if (iVar2 == 0) {
      iVar2 = FUN_0801e984(param_10);
      puVar3 = (undefined4 *)0x0;
      if (iVar2 == 0) {
        puVar3 = (undefined4 *)*param_10;
        unaff_r9 = param_10[2];
      }
      *param_10 = local_54;
      param_10[1] = local_50;
      param_10[2] = local_4c[0];
      local_54 = puVar3;
      uVar1 = unaff_r9;
      if (puVar3 == (undefined4 *)0x0) {
        local_54 = local_4c;
        uVar1 = local_4c[0];
      }
    }
    else {
      if (local_50 != 0) {
        FUN_0801ea32(*param_10,local_54,local_50);
      }
      FUN_0801e978(param_10,local_50);
      uVar1 = local_4c[0];
    }
    local_4c[0] = uVar1;
    local_50 = 0;
    *local_54 = 0;
    FUN_0801e9cc(&local_54);
  }
  else {
    *param_9 = local_58;
  }
  *param_1 = local_60;
  param_1[1] = local_5c;
  FUN_08009636(auStack_3c);
  return param_1;
}

