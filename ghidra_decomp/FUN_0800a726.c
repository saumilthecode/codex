
uint FUN_0800a726(int *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = FUN_0800a648();
  while( true ) {
    if (uVar1 <= param_3) {
      return 0xffffffff;
    }
    if (*(byte *)(*param_1 + param_3) != param_2) break;
    param_3 = param_3 + 1;
  }
  return param_3;
}

