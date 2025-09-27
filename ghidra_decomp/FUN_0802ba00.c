
undefined4 FUN_0802ba00(int param_1,undefined4 param_2,uint param_3,int param_4,undefined4 *param_5)

{
  switch(param_2) {
  case 0:
    if (param_4 != 0) {
      return 2;
    }
    if (0xf < param_3) {
      return 2;
    }
    *(undefined4 *)(param_1 + param_3 * 4 + 4) = *param_5;
    break;
  case 1:
  case 3:
  case 4:
    return 1;
  default:
    return 2;
  case 5:
    *(undefined4 *)(param_1 + 0x44) = *param_5;
  }
  return 0;
}

