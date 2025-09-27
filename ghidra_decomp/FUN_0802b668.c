
int FUN_0802b668(uint *param_1)

{
  uint uVar1;
  
  uVar1 = *param_1;
  if ((int)(uVar1 << 1) < 0) {
    uVar1 = uVar1 | 0x80000000;
  }
  else {
    uVar1 = uVar1 & 0x7fffffff;
  }
  return (int)param_1 + uVar1;
}

