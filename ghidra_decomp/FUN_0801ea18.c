
bool FUN_0801ea18(uint *param_1,uint param_2)

{
  if (param_2 < *param_1) {
    return true;
  }
  return *param_1 + param_1[1] * 4 < param_2;
}

