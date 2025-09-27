
bool FUN_0801fa4e(uint param_1)

{
  bool bVar1;
  
  if (((int)param_1 % 100 != 0) || (bVar1 = false, param_1 == ((int)param_1 / 400) * 400)) {
    bVar1 = (param_1 & 3) == 0;
  }
  return bVar1;
}

