
undefined4
FUN_0800c6cc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 param_9,undefined4 param_10,byte param_11)

{
  if (param_11 == 0x74) {
    FUN_08022670(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  else if (param_11 < 0x75) {
    if (param_11 == 100) {
      FUN_080226a8(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
    }
    else {
      FUN_08022718(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
    }
  }
  else if (param_11 == 0x77) {
    FUN_080226e0(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  else {
    FUN_08022750(param_1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  return param_1;
}

