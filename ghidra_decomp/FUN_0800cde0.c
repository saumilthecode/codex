
undefined4 FUN_0800cde0(undefined4 param_1,int param_2)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  
  uVar2 = CONCAT44(param_2,param_1);
  if (*(int *)(param_2 + 0x18) == 0) {
    uVar2 = FUN_080104fc(DAT_0800cdfc);
  }
  puVar1 = (undefined4 *)((ulonglong)uVar2 >> 0x20);
  FUN_0800bcd4((int)uVar2,*puVar1,puVar1[1]);
  return param_1;
}

