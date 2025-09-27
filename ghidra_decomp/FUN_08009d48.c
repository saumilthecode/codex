
undefined4 *
FUN_08009d48(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined1 param_8,
            undefined4 param_9,int *param_10,int param_11,undefined4 param_12)

{
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 local_2c [2];
  
  if (param_11 == 0) {
    local_2c[0] = DAT_08009ddc;
    FUN_08010dbc(&local_38,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,local_2c
                );
    if (*param_10 == 0) {
      FUN_08009150(param_12,local_2c);
    }
    *param_1 = local_38;
    param_1[1] = uStack_34;
    FUN_080091fc(local_2c[0]);
  }
  else {
    FUN_08010d7e(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,param_11);
  }
  return param_1;
}

