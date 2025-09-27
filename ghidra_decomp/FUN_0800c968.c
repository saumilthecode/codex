
undefined4 * FUN_0800c968(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar4 = DAT_0800cc28;
  puVar1 = (undefined4 *)FUN_0801ef04(param_1,DAT_0800cc2c,DAT_0800cc28,0xfffffffe,param_4);
  if (puVar1 == (undefined4 *)0x0) {
    if (param_2 == DAT_0800cc30) {
      puVar1 = (undefined4 *)FUN_08008466(0x14);
      puVar2 = (undefined4 *)FUN_08008466(0x68);
      *puVar2 = DAT_0800cc34;
      uVar3 = DAT_0800cc38;
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
      FUN_08020494(puVar1,0);
      iVar5 = *(int *)(param_1 + 4);
      puVar1[3] = param_1;
      *(int *)(param_1 + 4) = iVar5 + 1;
      *puVar1 = DAT_0800cc3c;
      puVar1[4] = puVar2;
      FUN_080096ea(0,param_1,puVar2);
    }
    else {
      if (param_2 == DAT_0800cc40) {
        puVar1 = (undefined4 *)FUN_08008466(0x10);
        puVar1[1] = 0;
        uVar3 = FUN_08008940();
        iVar5 = *(int *)(param_1 + 4);
        puVar1[2] = uVar3;
        puVar1[3] = param_1;
        *(int *)(param_1 + 4) = iVar5 + 1;
        uVar3 = DAT_0800cc44;
      }
      else if (param_2 == DAT_0800cc48) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800cc4c;
      }
      else if (param_2 == DAT_0800cc50) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800cc54;
      }
      else if (param_2 == DAT_0800cc58) {
        puVar1 = (undefined4 *)FUN_08008466(0xc);
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        puVar1[1] = 0;
        puVar1[2] = param_1;
        uVar3 = DAT_0800cc5c;
      }
      else {
        if (param_2 == DAT_0800cc60) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          puVar2 = (undefined4 *)FUN_08008466(0x44);
          *puVar2 = DAT_0800cc64;
          uVar3 = DAT_0800cc68;
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
          FUN_0801fe84(puVar1,0,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[3] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          *puVar1 = DAT_0800cc6c;
          puVar1[4] = puVar2;
          FUN_08009842(0,param_1,puVar2);
          return puVar1;
        }
        if (param_2 == DAT_0800cc70) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          puVar2 = (undefined4 *)FUN_08008466(0x44);
          *puVar2 = DAT_0800cc74;
          uVar3 = DAT_0800cc78;
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
          FUN_0801ff0c(puVar1,0,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[3] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          *puVar1 = DAT_0800cc7c;
          puVar1[4] = puVar2;
          FUN_080098ec(0,param_1,puVar2);
          return puVar1;
        }
        if (param_2 == DAT_0800cc80) {
          puVar1 = (undefined4 *)FUN_08008466(0x14);
          FUN_08022788(puVar1,0);
          iVar5 = *(int *)(param_1 + 4);
          puVar1[4] = param_1;
          *(int *)(param_1 + 4) = iVar5 + 1;
          uVar3 = DAT_0800cc84;
        }
        else {
          if (param_2 == DAT_0800cc88) {
            puVar1 = (undefined4 *)FUN_08008466(0x14);
            puVar2 = (undefined4 *)FUN_08008466(0x128);
            *puVar2 = DAT_0800cc8c;
            uVar3 = DAT_0800cc90;
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
            FUN_08020564(puVar1);
            iVar5 = *(int *)(param_1 + 4);
            puVar1[3] = param_1;
            *(int *)(param_1 + 4) = iVar5 + 1;
            *puVar1 = DAT_0800cc94;
            puVar1[4] = puVar2;
            FUN_08009764(0,param_1,puVar2);
            return puVar1;
          }
          if (param_2 == DAT_0800cc98) {
            puVar1 = (undefined4 *)FUN_08008466(0x10);
            puVar1[1] = 0;
            uVar3 = FUN_08008940();
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            puVar1[2] = uVar3;
            puVar1[3] = param_1;
            uVar3 = DAT_0800cc9c;
          }
          else if (param_2 == DAT_0800cca0) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800cca4;
          }
          else if (param_2 == DAT_0800cca8) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800ccac;
          }
          else if (param_2 == DAT_0800ccb0) {
            puVar1 = (undefined4 *)FUN_08008466(0xc);
            puVar1[1] = 0;
            puVar1[2] = param_1;
            *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
            uVar3 = DAT_0800ccb4;
          }
          else {
            if (param_2 == iRam0800cdb4) {
              puVar1 = (undefined4 *)FUN_08008466(0x14);
              puVar2 = (undefined4 *)FUN_08008466(0x70);
              *puVar2 = uRam0800cdb8;
              uVar3 = uRam0800cdbc;
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
              FUN_0801fffc(puVar1,0);
              iVar5 = *(int *)(param_1 + 4);
              puVar1[3] = param_1;
              *(int *)(param_1 + 4) = iVar5 + 1;
              *puVar1 = uRam0800cdc0;
              puVar1[4] = puVar2;
              FUN_08009996(0,param_1,puVar2);
              return puVar1;
            }
            if (param_2 == iRam0800cdc4) {
              puVar1 = (undefined4 *)FUN_08008466(0x14);
              puVar2 = (undefined4 *)FUN_08008466(0x70);
              *puVar2 = uRam0800cdc8;
              uVar3 = uRam0800cdcc;
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
              FUN_08020090(puVar1,0);
              iVar5 = *(int *)(param_1 + 4);
              puVar1[3] = param_1;
              *(int *)(param_1 + 4) = iVar5 + 1;
              *puVar1 = uRam0800cdd0;
              puVar1[4] = puVar2;
              FUN_08009a40(0,param_1,puVar2);
              return puVar1;
            }
            if (param_2 != iRam0800cdd4) {
              uVar3 = 0x800cdb3;
              FUN_080104fc(uRam0800cddc);
              uVar6 = 0xbc00000000;
              if (iRam000000d4 == 0) {
                uVar6 = FUN_080104fc(DAT_0800cdfc,0xbc,0x20,0,uVar4 >> 7,uVar3);
              }
              puVar1 = (undefined4 *)((ulonglong)uVar6 >> 0x20);
              FUN_0800bcd4((int)uVar6,*puVar1,puVar1[1]);
              return (undefined4 *)0x0;
            }
            puVar1 = (undefined4 *)FUN_08008466(0x14);
            FUN_0800e03c(puVar1,0);
            iVar5 = *(int *)(param_1 + 4);
            puVar1[4] = param_1;
            *(int *)(param_1 + 4) = iVar5 + 1;
            uVar3 = uRam0800cdd8;
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

