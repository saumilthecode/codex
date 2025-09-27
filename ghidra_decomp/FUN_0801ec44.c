
void FUN_0801ec44(int param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 4);
  if (uVar1 < param_2) {
    FUN_0801ec30(param_1,param_2 - uVar1);
  }
  else if (param_2 < uVar1) {
    FUN_0801e978();
  }
  return;
}

