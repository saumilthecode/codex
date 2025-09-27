
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 * FUN_08009e78(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int *extraout_r1;
  int *extraout_r1_00;
  int *piVar4;
  int iVar5;
  int *piStack_24;
  int iStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  
  iVar5 = DAT_0800a138;
  uStack_18 = param_4;
  puVar1 = (undefined4 *)FUN_0801ef04(param_1,DAT_0800a13c,DAT_0800a138,0xfffffffe);
  if (puVar1 == (undefined4 *)0x0) {
    if (param_2 == DAT_0800a140) {
      puVar1 = (undefined4 *)FUN_08008466(0x14);
      puVar2 = (undefined4 *)FUN_08008466(0x68);
      *puVar2 = DAT_0800a144;
      uVar3 = DAT_0800a148;
      puVar2[1] = 0;
      puVar2[2] = 0;
      puVar2[3] = 0;
      puVar2[5] = 0;
      puVar2[6] = 0;
      puVar2[7] = 0;
      puVar2[8] = 0;
      *(undefined1 *)(puVar2 + 4) = 0;
      *(undefined2 *)(puVar2 + 9) = 0;
      *(undefined1 *)(puVar2 + 0x19) = 0;
      *puVar1 = uVar3;
      puVar1[2] = puVar2;
      puVar1[1] = 0;
      FUN_08020638(puVar1,0);
      iVar5 = *(int *)(param_1 + 4);
      puVar1[3] = param_1;
      *(int *)(param_1 + 4) = iVar5 + 1;
      *puVar1 = DAT_0800a14c;
      puVar1[4] = puVar2;
      FUN_0800c1b8(0,param_1,puVar2);
    }
    else {
      if (param_2 == DAT_0800a150) {
        puVar1 = (undefined4 *)FUN_08008466(0x10);
        puVar1[1] = 0;
        uVar3 = FUN_08008940();
        iVar5 = *(int *)(param_1 + 4);
        puVar1[2] = uVar3;
        puVar1[3] = param_1;
        *(int *)(param_1 + 4) = iVar5 + 1;
        uVar3 = DAT_0800a154;
      }
      else if (param_2 == DAT_0800a158) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800a15c;
      }
      else if (param_2 == DAT_0800a160) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800a164;
      }
      else if (param_2 == DAT_0800a168) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800a16c;
      }
      else {
        if (param_2 == DAT_0800a170) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          puVar2 = (undefined4 *)FUN_08008466(0x44);
          *puVar2 = DAT_0800a174;
          uVar3 = DAT_0800a178;
          puVar2[1] = 0;
          puVar2[2] = 0;
          puVar2[3] = 0;
          puVar2[5] = 0;
          puVar2[6] = 0;
          puVar2[7] = 0;
          puVar2[8] = 0;
          puVar2[9] = 0;
          puVar2[10] = 0;
          puVar2[0xb] = 0;
          puVar2[0xc] = 0;
          *(undefined2 *)(puVar2 + 4) = 0;
          *(undefined1 *)((int)puVar2 + 0x12) = 0;
          puVar2[0xd] = 0;
          *(undefined1 *)((int)puVar2 + 0x43) = 0;
          *puVar1 = uVar3;
          puVar1[2] = puVar2;
          puVar1[1] = 0;
          FUN_0802018c(puVar1,0,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[3] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          *puVar1 = DAT_0800a17c;
          puVar1[4] = puVar2;
          FUN_0800c318(0,param_1,puVar2);
          return puVar1;
        }
        if (param_2 == DAT_0800a180) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          puVar2 = (undefined4 *)FUN_08008466(0x44);
          *puVar2 = DAT_0800a184;
          uVar3 = DAT_0800a188;
          puVar2[1] = 0;
          puVar2[2] = 0;
          puVar2[3] = 0;
          puVar2[5] = 0;
          puVar2[6] = 0;
          puVar2[7] = 0;
          puVar2[8] = 0;
          puVar2[9] = 0;
          puVar2[10] = 0;
          puVar2[0xb] = 0;
          puVar2[0xc] = 0;
          *(undefined2 *)(puVar2 + 4) = 0;
          *(undefined1 *)((int)puVar2 + 0x12) = 0;
          puVar2[0xd] = 0;
          *(undefined1 *)((int)puVar2 + 0x43) = 0;
          *puVar1 = uVar3;
          puVar1[2] = puVar2;
          puVar1[1] = 0;
          FUN_08020214(puVar1,0,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[3] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          *puVar1 = DAT_0800a18c;
          puVar1[4] = puVar2;
          FUN_0800c3c4(0,param_1,puVar2);
          return puVar1;
        }
        if (param_2 == DAT_0800a190) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          FUN_080111f4(puVar1,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[4] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          uVar3 = DAT_0800a194;
        }
        else {
          if (param_2 == DAT_0800a198) {
            puVar1 = (undefined4 *)FUN_08008466(0x14);
            puVar2 = (undefined4 *)FUN_08008466(0x128);
            *puVar2 = DAT_0800a19c;
            uVar3 = DAT_0800a1a0;
            puVar2[1] = 0;
            puVar2[2] = 0;
            puVar2[3] = 0;
            puVar2[5] = 0;
            puVar2[6] = 0;
            puVar2[7] = 0;
            puVar2[8] = 0;
            puVar2[9] = 0;
            puVar2[10] = 0;
            *(undefined1 *)(puVar2 + 4) = 0;
            *(undefined1 *)(puVar2 + 0x49) = 0;
            puVar1[1] = 0;
            *puVar1 = uVar3;
            puVar1[2] = puVar2;
            FUN_08020708(puVar1);
            iVar5 = *(int *)(param_1 + 4);
            puVar1[3] = param_1;
            *(int *)(param_1 + 4) = iVar5 + 1;
            *puVar1 = DAT_0800a1a4;
            puVar1[4] = puVar2;
            FUN_0800c234(0,param_1,puVar2);
            return puVar1;
          }
          if (param_2 == DAT_0800a1a8) {
            puVar1 = (undefined4 *)FUN_08008466(0x10);
            puVar1[1] = 0;
            uVar3 = FUN_08008940();
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            puVar1[2] = uVar3;
            puVar1[3] = param_1;
            uVar3 = DAT_0800a1ac;
          }
          else if (param_2 == DAT_0800a1b0) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800a1b4;
          }
          else if (param_2 == DAT_0800a1b8) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800a1bc;
          }
          else if (param_2 == DAT_0800a1c0) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800a1c4;
          }
          else {
            if (param_2 == iRam0800a2c4) {
              puVar1 = (undefined4 *)FUN_08008466(0x14);
              puVar2 = (undefined4 *)FUN_08008466(0x70);
              *puVar2 = uRam0800a2c8;
              uVar3 = uRam0800a2cc;
              puVar2[1] = 0;
              puVar2[2] = 0;
              puVar2[3] = 0;
              puVar2[5] = 0;
              puVar2[6] = 0;
              puVar2[7] = 0;
              puVar2[8] = 0;
              puVar2[9] = 0;
              puVar2[10] = 0;
              puVar2[0xb] = 0;
              puVar2[0xc] = 0;
              puVar2[0xd] = 0;
              puVar2[0xe] = 0;
              *(undefined1 *)(puVar2 + 4) = 0;
              puVar2[0xf] = 0;
              *(undefined1 *)(puVar2 + 0x1b) = 0;
              puVar1[1] = 0;
              *puVar1 = uVar3;
              puVar1[2] = puVar2;
              FUN_08020304(puVar1,0);
              iVar5 = *(int *)(param_1 + 4);
              puVar1[3] = param_1;
              *(int *)(param_1 + 4) = iVar5 + 1;
              *puVar1 = uRam0800a2d0;
              puVar1[4] = puVar2;
              FUN_0800c470(0,param_1,puVar2);
              return puVar1;
            }
            if (param_2 == iRam0800a2d4) {
              puVar1 = (undefined4 *)FUN_08008466(0x14);
              puVar2 = (undefined4 *)FUN_08008466(0x70);
              *puVar2 = uRam0800a2d8;
              uVar3 = uRam0800a2dc;
              puVar2[1] = 0;
              puVar2[2] = 0;
              puVar2[3] = 0;
              puVar2[5] = 0;
              puVar2[6] = 0;
              puVar2[7] = 0;
              puVar2[8] = 0;
              puVar2[9] = 0;
              puVar2[10] = 0;
              puVar2[0xb] = 0;
              puVar2[0xc] = 0;
              puVar2[0xd] = 0;
              puVar2[0xe] = 0;
              *(undefined1 *)(puVar2 + 4) = 0;
              puVar2[0xf] = 0;
              *(undefined1 *)(puVar2 + 0x1b) = 0;
              puVar1[1] = 0;
              *puVar1 = uVar3;
              puVar1[2] = puVar2;
              FUN_08020398(puVar1,0);
              iVar5 = *(int *)(param_1 + 4);
              puVar1[3] = param_1;
              *(int *)(param_1 + 4) = iVar5 + 1;
              *puVar1 = uRam0800a2e0;
              puVar1[4] = puVar2;
              FUN_0800c51c(0,param_1,puVar2);
              return puVar1;
            }
            if (param_2 != iRam0800a2e4) {
              uVar3 = 0x800a2c3;
              FUN_080104fc(uRam0800a2ec);
              iStack_20 = iVar5 + 0x104;
              piVar4 = extraout_r1;
              piStack_24 = extraout_r1;
              uStack_1c = uVar3;
              if (extraout_r1[6] == 0) {
                FUN_080104fc(DAT_0800a314);
                piVar4 = extraout_r1_00;
              }
              _MasterStackPointer = FUN_080090e8(*piVar4,piVar4[1] + *piVar4,&piStack_24);
              return (undefined4 *)0x0;
            }
            puVar1 = (undefined4 *)FUN_08008466(0x14);
            FUN_08018e14(puVar1,0);
            iVar5 = *(int *)(param_1 + 4);
            puVar1[4] = param_1;
            *(int *)(param_1 + 4) = iVar5 + 1;
            uVar3 = uRam0800a2e8;
          }
        }
      }
      *puVar1 = uVar3;
    }
  }
  else {
    puVar1 = (undefined4 *)*puVar1;
  }
  return puVar1;
}

