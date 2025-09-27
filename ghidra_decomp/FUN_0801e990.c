
void FUN_0801e990(undefined4 param_1,uint *param_2,uint param_3)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  
  uVar4 = CONCAT44(param_2,param_1);
  uVar2 = *param_2;
  if (0xfffffff < uVar2) {
    uVar4 = FUN_08010502(DAT_0801e9c8);
  }
  puVar1 = (uint *)((ulonglong)uVar4 >> 0x20);
  if ((param_3 < uVar2) && (uVar3 = param_3 << 1, uVar2 < param_3 << 1)) {
    if (uVar3 < 0x10000000) {
      *puVar1 = uVar3;
      uVar2 = uVar3;
    }
    else {
      uVar2 = 0xfffffff;
      *puVar1 = 0xfffffff;
    }
  }
  FUN_0801e958((int)uVar4,uVar2 + 1);
  return;
}

