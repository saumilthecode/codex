
undefined4 *
FUN_08008db6(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined1 param_7,undefined4 param_8,int *param_9
            ,undefined4 *param_10)

{
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 local_30;
  undefined4 local_2c;
  int local_24;
  undefined4 local_20;
  undefined4 uStack_1c;
  
  local_24 = 0;
  local_30 = param_3;
  local_2c = param_4;
  FUN_0800c834(&local_38,0,*(undefined4 *)(param_2 + 8),param_3,param_4,param_5,param_6,param_7,
               param_8,&local_24,&local_20,0);
  if (local_24 == 0) {
    *param_10 = local_20;
    param_10[1] = uStack_1c;
  }
  else {
    *param_9 = local_24;
  }
  *param_1 = local_38;
  param_1[1] = uStack_34;
  return param_1;
}

