
undefined4
FUN_08009c94(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 param_9,undefined4 param_10,byte param_11)

{
  if (param_11 == 0x74) {
    FUN_08018cfc(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  else if (param_11 < 0x75) {
    if (param_11 == 100) {
      FUN_08018d34(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
    }
    else {
      FUN_08018da4(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
    }
  }
  else if (param_11 == 0x77) {
    FUN_08018d6c(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  else {
    FUN_08018ddc(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  return param_1;
}

