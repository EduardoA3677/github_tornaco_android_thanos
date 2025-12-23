.class public final Llyiahf/vczjk/pc7;
.super Llyiahf/vczjk/sg3;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/pc7;


# instance fields
.field private bitField0_:I

.field private compilerPluginData_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ac7;",
            ">;"
        }
    .end annotation
.end field

.field private contextReceiverTypeIdMemoizedSerializedSize:I

.field private contextReceiverTypeId_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private contextReceiverType_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/hd7;",
            ">;"
        }
    .end annotation
.end field

.field private contract_:Llyiahf/vczjk/ec7;

.field private flags_:I

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private name_:I

.field private oldFlags_:I

.field private receiverTypeId_:I

.field private receiverType_:Llyiahf/vczjk/hd7;

.field private returnTypeId_:I

.field private returnType_:Llyiahf/vczjk/hd7;

.field private typeParameter_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/md7;",
            ">;"
        }
    .end annotation
.end field

.field private typeTable_:Llyiahf/vczjk/nd7;

.field private final unknownFields:Llyiahf/vczjk/im0;

.field private valueParameter_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/pd7;",
            ">;"
        }
    .end annotation
.end field

.field private versionRequirement_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0xf

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/pc7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/pc7;

    invoke-direct {v0}, Llyiahf/vczjk/pc7;-><init>()V

    sput-object v0, Llyiahf/vczjk/pc7;->OooOOO0:Llyiahf/vczjk/pc7;

    invoke-virtual {v0}, Llyiahf/vczjk/pc7;->OooooOo()V

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeIdMemoizedSerializedSize:I

    iput-byte v0, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/pc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 17

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    invoke-direct {v1}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v3, -0x1

    iput v3, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeIdMemoizedSerializedSize:I

    iput-byte v3, v1, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    iput v3, v1, Llyiahf/vczjk/pc7;->memoizedSerializedSize:I

    invoke-virtual {v1}, Llyiahf/vczjk/pc7;->OooooOo()V

    new-instance v3, Llyiahf/vczjk/hm0;

    invoke-direct {v3}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v4, 0x1

    invoke-static {v3, v4}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v5

    const/4 v6, 0x0

    move v7, v6

    :goto_0
    const/16 v8, 0x4000

    const/16 v9, 0x400

    const/16 v10, 0x20

    const/16 v11, 0x100

    const/16 v12, 0x200

    const/16 v13, 0x1000

    if-nez v6, :cond_19

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v14

    const/4 v15, 0x0

    sparse-switch v14, :sswitch_data_0

    invoke-virtual {v1, v0, v5, v2, v14}, Llyiahf/vczjk/sg3;->OooOO0o(Llyiahf/vczjk/h11;Llyiahf/vczjk/n11;Llyiahf/vczjk/iu2;I)Z

    move-result v8

    if-nez v8, :cond_1

    move v6, v4

    move/from16 v16, v6

    goto/16 :goto_4

    :catchall_0
    move-exception v0

    goto/16 :goto_7

    :catch_0
    move-exception v0

    goto/16 :goto_5

    :catch_1
    move-exception v0

    goto/16 :goto_6

    :sswitch_0
    and-int/lit16 v14, v7, 0x4000

    if-eq v14, v8, :cond_0

    new-instance v14, Ljava/util/ArrayList;

    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    iput-object v14, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x4000

    :cond_0
    iget-object v14, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    sget-object v15, Llyiahf/vczjk/ac7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v15, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v15

    invoke-interface {v14, v15}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_1
    move/from16 v16, v4

    goto/16 :goto_4

    :sswitch_1
    iget v14, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    and-int/2addr v14, v11

    if-ne v14, v11, :cond_2

    iget-object v14, v1, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v15, Llyiahf/vczjk/dc7;

    move/from16 v16, v4

    const/4 v4, 0x0

    invoke-direct {v15, v4}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v4, v15, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v15, v14}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    goto :goto_1

    :cond_2
    move/from16 v16, v4

    :goto_1
    sget-object v4, Llyiahf/vczjk/ec7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ec7;

    iput-object v4, v1, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    if-eqz v15, :cond_3

    invoke-virtual {v15, v4}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    invoke-virtual {v15}, Llyiahf/vczjk/dc7;->OooO0o0()Llyiahf/vczjk/ec7;

    move-result-object v4

    iput-object v4, v1, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    :cond_3
    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/2addr v4, v11

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    goto/16 :goto_4

    :sswitch_2
    move/from16 v16, v4

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/h11;->OooO0Oo(I)I

    move-result v4

    and-int/lit16 v14, v7, 0x1000

    if-eq v14, v13, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v14

    if-lez v14, :cond_4

    new-instance v14, Ljava/util/ArrayList;

    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    iput-object v14, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x1000

    :cond_4
    :goto_2
    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v14

    if-lez v14, :cond_5

    iget-object v14, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v15

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-interface {v14, v15}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_5
    invoke-virtual {v0, v4}, Llyiahf/vczjk/h11;->OooO0OO(I)V

    goto/16 :goto_4

    :sswitch_3
    move/from16 v16, v4

    and-int/lit16 v4, v7, 0x1000

    if-eq v4, v13, :cond_6

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iput-object v4, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x1000

    :cond_6
    iget-object v4, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v14

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-interface {v4, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_4

    :sswitch_4
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v14, 0x80

    and-int/2addr v4, v14

    if-ne v4, v14, :cond_7

    iget-object v4, v1, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/nd7;->OooOO0o(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/vb7;

    move-result-object v15

    :cond_7
    sget-object v4, Llyiahf/vczjk/nd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/nd7;

    iput-object v4, v1, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    if-eqz v15, :cond_8

    invoke-virtual {v15, v4}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    invoke-virtual {v15}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v4

    iput-object v4, v1, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    :cond_8
    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/2addr v4, v14

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    goto/16 :goto_4

    :sswitch_5
    move/from16 v16, v4

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/h11;->OooO0Oo(I)I

    move-result v4

    and-int/lit16 v14, v7, 0x200

    if-eq v14, v12, :cond_9

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v14

    if-lez v14, :cond_9

    new-instance v14, Ljava/util/ArrayList;

    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    iput-object v14, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x200

    :cond_9
    :goto_3
    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v14

    if-lez v14, :cond_a

    iget-object v14, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v15

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-interface {v14, v15}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_a
    invoke-virtual {v0, v4}, Llyiahf/vczjk/h11;->OooO0OO(I)V

    goto/16 :goto_4

    :sswitch_6
    move/from16 v16, v4

    and-int/lit16 v4, v7, 0x200

    if-eq v4, v12, :cond_b

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iput-object v4, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x200

    :cond_b
    iget-object v4, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v14

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-interface {v4, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_4

    :sswitch_7
    move/from16 v16, v4

    and-int/lit16 v4, v7, 0x100

    if-eq v4, v11, :cond_c

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iput-object v4, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x100

    :cond_c
    iget-object v4, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    sget-object v14, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v14, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v14

    invoke-interface {v4, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_4

    :sswitch_8
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/lit8 v4, v4, 0x1

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, v1, Llyiahf/vczjk/pc7;->flags_:I

    goto/16 :goto_4

    :sswitch_9
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/lit8 v4, v4, 0x40

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, v1, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    goto/16 :goto_4

    :sswitch_a
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/lit8 v4, v4, 0x10

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, v1, Llyiahf/vczjk/pc7;->returnTypeId_:I

    goto/16 :goto_4

    :sswitch_b
    move/from16 v16, v4

    and-int/lit16 v4, v7, 0x400

    if-eq v4, v9, :cond_d

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iput-object v4, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    or-int/lit16 v7, v7, 0x400

    :cond_d
    iget-object v4, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    sget-object v14, Llyiahf/vczjk/pd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v14, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v14

    invoke-interface {v4, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_4

    :sswitch_c
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    and-int/2addr v4, v10

    if-ne v4, v10, :cond_e

    iget-object v4, v1, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v15

    :cond_e
    sget-object v4, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/hd7;

    iput-object v4, v1, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    if-eqz v15, :cond_f

    invoke-virtual {v15, v4}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v15}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v4

    iput-object v4, v1, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    :cond_f
    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/2addr v4, v10

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    goto :goto_4

    :sswitch_d
    move/from16 v16, v4

    and-int/lit8 v4, v7, 0x20

    if-eq v4, v10, :cond_10

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iput-object v4, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    or-int/lit8 v7, v7, 0x20

    :cond_10
    iget-object v4, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    sget-object v14, Llyiahf/vczjk/md7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v14, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v14

    invoke-interface {v4, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :sswitch_e
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v14, 0x8

    and-int/2addr v4, v14

    if-ne v4, v14, :cond_11

    iget-object v4, v1, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v15

    :cond_11
    sget-object v4, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/hd7;

    iput-object v4, v1, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    if-eqz v15, :cond_12

    invoke-virtual {v15, v4}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v15}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v4

    iput-object v4, v1, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    :cond_12
    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/2addr v4, v14

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    goto :goto_4

    :sswitch_f
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/lit8 v4, v4, 0x4

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, v1, Llyiahf/vczjk/pc7;->name_:I

    goto :goto_4

    :sswitch_10
    move/from16 v16, v4

    iget v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    or-int/lit8 v4, v4, 0x2

    iput v4, v1, Llyiahf/vczjk/pc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, v1, Llyiahf/vczjk/pc7;->oldFlags_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_4

    :sswitch_11
    move/from16 v16, v4

    move/from16 v6, v16

    :goto_4
    move/from16 v4, v16

    goto/16 :goto_0

    :goto_5
    :try_start_1
    new-instance v2, Llyiahf/vczjk/i44;

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v2

    :goto_6
    invoke-virtual {v0, v1}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_7
    and-int/lit8 v2, v7, 0x20

    if-ne v2, v10, :cond_13

    iget-object v2, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    :cond_13
    and-int/lit16 v2, v7, 0x400

    if-ne v2, v9, :cond_14

    iget-object v2, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    :cond_14
    and-int/lit16 v2, v7, 0x100

    if-ne v2, v11, :cond_15

    iget-object v2, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    :cond_15
    and-int/lit16 v2, v7, 0x200

    if-ne v2, v12, :cond_16

    iget-object v2, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    :cond_16
    and-int/lit16 v2, v7, 0x1000

    if-ne v2, v13, :cond_17

    iget-object v2, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    :cond_17
    and-int/lit16 v2, v7, 0x4000

    if-ne v2, v8, :cond_18

    iget-object v2, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    :cond_18
    :try_start_2
    invoke-virtual {v5}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_8

    :catchall_1
    move-exception v0

    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    throw v0

    :goto_8
    invoke-virtual {v1}, Llyiahf/vczjk/sg3;->OooOO0O()V

    throw v0

    :cond_19
    and-int/lit8 v0, v7, 0x20

    if-ne v0, v10, :cond_1a

    iget-object v0, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    :cond_1a
    and-int/lit16 v0, v7, 0x400

    if-ne v0, v9, :cond_1b

    iget-object v0, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    :cond_1b
    and-int/lit16 v0, v7, 0x100

    if-ne v0, v11, :cond_1c

    iget-object v0, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    :cond_1c
    and-int/lit16 v0, v7, 0x200

    if-ne v0, v12, :cond_1d

    iget-object v0, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    :cond_1d
    and-int/lit16 v0, v7, 0x1000

    if-ne v0, v13, :cond_1e

    iget-object v0, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    :cond_1e
    and-int/lit16 v0, v7, 0x4000

    if-ne v0, v8, :cond_1f

    iget-object v0, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    :cond_1f
    :try_start_3
    invoke-virtual {v5}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catch_3
    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_9

    :catchall_2
    move-exception v0

    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    throw v0

    :goto_9
    invoke-virtual {v1}, Llyiahf/vczjk/sg3;->OooOO0O()V

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_11
        0x8 -> :sswitch_10
        0x10 -> :sswitch_f
        0x1a -> :sswitch_e
        0x22 -> :sswitch_d
        0x2a -> :sswitch_c
        0x32 -> :sswitch_b
        0x38 -> :sswitch_a
        0x40 -> :sswitch_9
        0x48 -> :sswitch_8
        0x52 -> :sswitch_7
        0x58 -> :sswitch_6
        0x5a -> :sswitch_5
        0xf2 -> :sswitch_4
        0xf8 -> :sswitch_3
        0xfa -> :sswitch_2
        0x102 -> :sswitch_1
        0x10a -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Llyiahf/vczjk/oc7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg3;-><init>(Llyiahf/vczjk/rg3;)V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeIdMemoizedSerializedSize:I

    iput-byte v0, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/pc7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->flags_:I

    return-void
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->oldFlags_:I

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->name_:I

    return-void
.end method

.method public static synthetic OooOOo(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->returnTypeId_:I

    return-void
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/pc7;Llyiahf/vczjk/hd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    return-void
.end method

.method public static synthetic OooOOoo(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOo(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOo0(Llyiahf/vczjk/pc7;Llyiahf/vczjk/hd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    return-void
.end method

.method public static synthetic OooOo00(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOo0O(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    return-void
.end method

.method public static synthetic OooOo0o(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOoO(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOoO0(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOoOO(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOoo(Llyiahf/vczjk/pc7;Llyiahf/vczjk/nd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    return-void
.end method

.method public static synthetic OooOoo0(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOooO(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOooo(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    return-void
.end method

.method public static synthetic Oooo0(Llyiahf/vczjk/pc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    return-void
.end method

.method public static synthetic Oooo000(Llyiahf/vczjk/pc7;Llyiahf/vczjk/ec7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    return-void
.end method

.method public static synthetic Oooo00O(Llyiahf/vczjk/pc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic Oooo00o(Llyiahf/vczjk/pc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    return-void
.end method

.method public static synthetic Oooo0O0(Llyiahf/vczjk/pc7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->getSerializedSize()I

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/sg3;)V

    iget v1, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    const/4 v3, 0x1

    if-ne v1, v2, :cond_0

    iget v1, p0, Llyiahf/vczjk/pc7;->oldFlags_:I

    invoke-virtual {p1, v3, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    iget v1, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v4, 0x4

    and-int/2addr v1, v4

    if-ne v1, v4, :cond_1

    iget v1, p0, Llyiahf/vczjk/pc7;->name_:I

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_1
    iget v1, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v2, 0x8

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_2

    const/4 v1, 0x3

    iget-object v5, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    invoke-virtual {p1, v1, v5}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_2
    const/4 v1, 0x0

    move v5, v1

    :goto_0
    iget-object v6, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    if-ge v5, v6, :cond_3

    iget-object v6, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v6, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pi5;

    invoke-virtual {p1, v4, v6}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_3
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v5, 0x20

    and-int/2addr v4, v5

    if-ne v4, v5, :cond_4

    const/4 v4, 0x5

    iget-object v6, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    invoke-virtual {p1, v4, v6}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_4
    move v4, v1

    :goto_1
    iget-object v6, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    if-ge v4, v6, :cond_5

    iget-object v6, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v6, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pi5;

    const/4 v7, 0x6

    invoke-virtual {p1, v7, v6}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_5
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v6, 0x10

    and-int/2addr v4, v6

    if-ne v4, v6, :cond_6

    const/4 v4, 0x7

    iget v6, p0, Llyiahf/vczjk/pc7;->returnTypeId_:I

    invoke-virtual {p1, v4, v6}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_6
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v6, 0x40

    and-int/2addr v4, v6

    if-ne v4, v6, :cond_7

    iget v4, p0, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    invoke-virtual {p1, v2, v4}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_7
    iget v2, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    and-int/2addr v2, v3

    if-ne v2, v3, :cond_8

    const/16 v2, 0x9

    iget v3, p0, Llyiahf/vczjk/pc7;->flags_:I

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_8
    move v2, v1

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_9

    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/16 v4, 0xa

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_9
    iget-object v2, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-lez v2, :cond_a

    const/16 v2, 0x5a

    invoke-virtual {p1, v2}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    iget v2, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeIdMemoizedSerializedSize:I

    invoke-virtual {p1, v2}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    :cond_a
    move v2, v1

    :goto_3
    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_b

    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Integer;

    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/n11;->OooOoo0(I)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    :cond_b
    iget v2, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v3, 0x80

    and-int/2addr v2, v3

    if-ne v2, v3, :cond_c

    const/16 v2, 0x1e

    iget-object v3, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_c
    move v2, v1

    :goto_4
    iget-object v3, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_d

    iget-object v3, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Integer;

    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    const/16 v4, 0x1f

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_4

    :cond_d
    iget v2, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v3, 0x100

    and-int/2addr v2, v3

    if-ne v2, v3, :cond_e

    iget-object v2, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    invoke-virtual {p1, v5, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_e
    :goto_5
    iget-object v2, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_f

    iget-object v2, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pi5;

    const/16 v3, 0x21

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_5

    :cond_f
    const/16 v1, 0x4a38

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n62;->o000OO(ILlyiahf/vczjk/n11;)V

    iget-object v0, p0, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final Oooo()Llyiahf/vczjk/hd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    return-object v0
.end method

.method public final Oooo0OO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    return-object v0
.end method

.method public final Oooo0o()Llyiahf/vczjk/ec7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    return-object v0
.end method

.method public final Oooo0o0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    return-object v0
.end method

.method public final Oooo0oO()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc7;->name_:I

    return v0
.end method

.method public final Oooo0oo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc7;->oldFlags_:I

    return v0
.end method

.method public final OoooO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    return-object v0
.end method

.method public final OoooO0()Llyiahf/vczjk/hd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    return-object v0
.end method

.method public final OoooO00()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    return v0
.end method

.method public final OoooO0O()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc7;->returnTypeId_:I

    return v0
.end method

.method public final OoooOO0()Llyiahf/vczjk/nd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    return-object v0
.end method

.method public final OoooOOO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOOo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOo0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOoO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOoo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Ooooo00()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x40

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Ooooo0o()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooooO0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooooOO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x80

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooooOo()V
    .locals 3

    const/4 v0, 0x6

    iput v0, p0, Llyiahf/vczjk/pc7;->flags_:I

    iput v0, p0, Llyiahf/vczjk/pc7;->oldFlags_:I

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/pc7;->name_:I

    sget-object v1, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v1, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    iput v0, p0, Llyiahf/vczjk/pc7;->returnTypeId_:I

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v2, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    iput-object v1, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    iput v0, p0, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    iput-object v2, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    iput-object v2, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    iput-object v2, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v0, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    iput-object v2, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/ec7;->OooOOO0:Llyiahf/vczjk/ec7;

    iput-object v0, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    iput-object v2, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    return-void
.end method

.method public final getDefaultInstanceForType()Llyiahf/vczjk/pi5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/pc7;->OooOOO0:Llyiahf/vczjk/pc7;

    return-object v0
.end method

.method public final getFlags()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc7;->flags_:I

    return v0
.end method

.method public final getSerializedSize()I
    .locals 9

    iget v0, p0, Llyiahf/vczjk/pc7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/pc7;->oldFlags_:I

    invoke-static {v3, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/4 v5, 0x4

    and-int/2addr v4, v5

    if-ne v4, v5, :cond_2

    iget v4, p0, Llyiahf/vczjk/pc7;->name_:I

    invoke-static {v1, v4}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v4

    add-int/2addr v0, v4

    :cond_2
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v6, 0x8

    and-int/2addr v4, v6

    if-ne v4, v6, :cond_3

    const/4 v4, 0x3

    iget-object v7, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    invoke-static {v4, v7}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v4

    add-int/2addr v0, v4

    :cond_3
    move v4, v2

    :goto_1
    iget-object v7, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    if-ge v4, v7, :cond_4

    iget-object v7, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v7, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/pi5;

    invoke-static {v5, v7}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v7

    add-int/2addr v0, v7

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_4
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v5, 0x20

    and-int/2addr v4, v5

    if-ne v4, v5, :cond_5

    const/4 v4, 0x5

    iget-object v7, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    invoke-static {v4, v7}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v4

    add-int/2addr v0, v4

    :cond_5
    move v4, v2

    :goto_2
    iget-object v7, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    if-ge v4, v7, :cond_6

    iget-object v7, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v7, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/pi5;

    const/4 v8, 0x6

    invoke-static {v8, v7}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v7

    add-int/2addr v0, v7

    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_6
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v7, 0x10

    and-int/2addr v4, v7

    if-ne v4, v7, :cond_7

    const/4 v4, 0x7

    iget v7, p0, Llyiahf/vczjk/pc7;->returnTypeId_:I

    invoke-static {v4, v7}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v4

    add-int/2addr v0, v4

    :cond_7
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v7, 0x40

    and-int/2addr v4, v7

    if-ne v4, v7, :cond_8

    iget v4, p0, Llyiahf/vczjk/pc7;->receiverTypeId_:I

    invoke-static {v6, v4}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v4

    add-int/2addr v0, v4

    :cond_8
    iget v4, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    and-int/2addr v4, v3

    if-ne v4, v3, :cond_9

    const/16 v3, 0x9

    iget v4, p0, Llyiahf/vczjk/pc7;->flags_:I

    invoke-static {v3, v4}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v3

    add-int/2addr v0, v3

    :cond_9
    move v3, v2

    :goto_3
    iget-object v4, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    if-ge v3, v4, :cond_a

    iget-object v4, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/pi5;

    const/16 v6, 0xa

    invoke-static {v6, v4}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v4

    add-int/2addr v0, v4

    add-int/lit8 v3, v3, 0x1

    goto :goto_3

    :cond_a
    move v3, v2

    move v4, v3

    :goto_4
    iget-object v6, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    if-ge v3, v6, :cond_b

    iget-object v6, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v6, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Integer;

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6

    invoke-static {v6}, Llyiahf/vczjk/n11;->OooO0o(I)I

    move-result v6

    add-int/2addr v4, v6

    add-int/lit8 v3, v3, 0x1

    goto :goto_4

    :cond_b
    add-int/2addr v0, v4

    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeId_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_c

    add-int/lit8 v0, v0, 0x1

    invoke-static {v4}, Llyiahf/vczjk/n11;->OooO0o(I)I

    move-result v3

    add-int/2addr v0, v3

    :cond_c
    iput v4, p0, Llyiahf/vczjk/pc7;->contextReceiverTypeIdMemoizedSerializedSize:I

    iget v3, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v4, 0x80

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_d

    const/16 v3, 0x1e

    iget-object v4, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-static {v3, v4}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v3

    add-int/2addr v0, v3

    :cond_d
    move v3, v2

    move v4, v3

    :goto_5
    iget-object v6, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    if-ge v3, v6, :cond_e

    iget-object v6, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-interface {v6, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Integer;

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6

    invoke-static {v6}, Llyiahf/vczjk/n11;->OooO0o(I)I

    move-result v6

    add-int/2addr v4, v6

    add-int/lit8 v3, v3, 0x1

    goto :goto_5

    :cond_e
    add-int/2addr v0, v4

    iget-object v3, p0, Llyiahf/vczjk/pc7;->versionRequirement_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    mul-int/2addr v3, v1

    add-int/2addr v3, v0

    iget v0, p0, Llyiahf/vczjk/pc7;->bitField0_:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_f

    iget-object v0, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    invoke-static {v5, v0}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v0

    add-int/2addr v3, v0

    :cond_f
    :goto_6
    iget-object v0, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-ge v2, v0, :cond_10

    iget-object v0, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pi5;

    const/16 v1, 0x21

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v0

    add-int/2addr v3, v0

    add-int/lit8 v2, v2, 0x1

    goto :goto_6

    :cond_10
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o()I

    move-result v0

    add-int/2addr v0, v3

    iget-object v1, p0, Llyiahf/vczjk/pc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/pc7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->OoooOo0()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->Ooooo0o()Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/pc7;->returnType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v0}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_3
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/pc7;->typeParameter_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/md7;

    invoke-virtual {v3}, Llyiahf/vczjk/md7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_4

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->OoooOoo()Z

    move-result v0

    if-eqz v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/pc7;->receiverType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v0}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_6

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_6
    move v0, v2

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_8

    iget-object v3, p0, Llyiahf/vczjk/pc7;->contextReceiverType_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hd7;

    invoke-virtual {v3}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_7

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_7
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_8
    move v0, v2

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_a

    iget-object v3, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pd7;

    invoke-virtual {v3}, Llyiahf/vczjk/pd7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_9

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_9
    add-int/lit8 v0, v0, 0x1

    goto :goto_2

    :cond_a
    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->OooooOO()Z

    move-result v0

    if-eqz v0, :cond_b

    iget-object v0, p0, Llyiahf/vczjk/pc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {v0}, Llyiahf/vczjk/nd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_b

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_b
    invoke-virtual {p0}, Llyiahf/vczjk/pc7;->OoooOOO()Z

    move-result v0

    if-eqz v0, :cond_c

    iget-object v0, p0, Llyiahf/vczjk/pc7;->contract_:Llyiahf/vczjk/ec7;

    invoke-virtual {v0}, Llyiahf/vczjk/ec7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_c

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_c
    move v0, v2

    :goto_3
    iget-object v3, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_e

    iget-object v3, p0, Llyiahf/vczjk/pc7;->compilerPluginData_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ac7;

    invoke-virtual {v3}, Llyiahf/vczjk/ac7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_d

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_d
    add-int/lit8 v0, v0, 0x1

    goto :goto_3

    :cond_e
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_f

    iput-byte v2, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v2

    :cond_f
    iput-byte v1, p0, Llyiahf/vczjk/pc7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/oc7;->OooO0oo()Llyiahf/vczjk/oc7;

    move-result-object v0

    return-object v0
.end method

.method public final o000oOoO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc7;->valueParameter_:Ljava/util/List;

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/oc7;->OooO0oo()Llyiahf/vczjk/oc7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/oc7;->OooO(Llyiahf/vczjk/pc7;)V

    return-object v0
.end method
