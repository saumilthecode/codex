
undefined4 *
FUN_0800c8ce(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined1 param_8,
            undefined4 param_9,int *param_10,int param_11,undefined4 param_12)

{
  undefined4 local_48;
  undefined4 uStack_44;
  int *local_40;
  int iStack_3c;
  int local_38 [5];
  
  if (param_11 == 0) {
    local_40 = local_38;
    iStack_3c = param_11;
    local_38[0] = param_11;
    FUN_0800d7b6(&local_48,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 &local_40);
    if (*param_10 == 0) {
      FUN_0800bd1c(param_12,&local_40);
    }
    *param_1 = local_48;
    param_1[1] = uStack_44;
    FUN_0801e9cc(&local_40);
  }
  else {
    FUN_0800d778(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,param_11);
  }
  return param_1;
}

