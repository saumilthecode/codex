
void FUN_08017fa0(undefined4 *param_1,uint param_2,undefined1 param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  uVar2 = param_1[1];
  if (uVar2 < param_2) {
    FUN_08017f8c(param_1,param_2 - uVar2);
  }
  else {
    puVar1 = param_1;
    if (param_2 < uVar2) {
      puVar1 = (undefined4 *)*param_1;
    }
    if (param_2 < uVar2) {
      param_1[1] = param_2;
      param_3 = 0;
    }
    if (param_2 < uVar2) {
      *(undefined1 *)((int)puVar1 + param_2) = param_3;
    }
  }
  return;
}

