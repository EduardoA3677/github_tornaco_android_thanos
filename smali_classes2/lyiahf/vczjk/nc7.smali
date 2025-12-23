.class public final Llyiahf/vczjk/nc7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/nc7;


# instance fields
.field private andArgument_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/nc7;",
            ">;"
        }
    .end annotation
.end field

.field private bitField0_:I

.field private constantValue_:Llyiahf/vczjk/mc7;

.field private flags_:I

.field private isInstanceTypeId_:I

.field private isInstanceType_:Llyiahf/vczjk/hd7;

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private orArgument_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/nc7;",
            ">;"
        }
    .end annotation
.end field

.field private final unknownFields:Llyiahf/vczjk/im0;

.field private valueParameterReference_:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/nc7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/nc7;

    invoke-direct {v0}, Llyiahf/vczjk/nc7;-><init>()V

    sput-object v0, Llyiahf/vczjk/nc7;->OooOOO0:Llyiahf/vczjk/nc7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/nc7;->flags_:I

    iput v1, v0, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    sget-object v2, Llyiahf/vczjk/mc7;->OooOOO0:Llyiahf/vczjk/mc7;

    iput-object v2, v0, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    sget-object v2, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v2, v0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    iput v1, v0, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/nc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 17

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    invoke-direct {v1}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v3, -0x1

    iput-byte v3, v1, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    iput v3, v1, Llyiahf/vczjk/nc7;->memoizedSerializedSize:I

    const/4 v3, 0x0

    iput v3, v1, Llyiahf/vczjk/nc7;->flags_:I

    iput v3, v1, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    sget-object v4, Llyiahf/vczjk/mc7;->OooOOO0:Llyiahf/vczjk/mc7;

    iput-object v4, v1, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    sget-object v5, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v5, v1, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    iput v3, v1, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    sget-object v5, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v5, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    iput-object v5, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    new-instance v5, Llyiahf/vczjk/hm0;

    invoke-direct {v5}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v6, 0x1

    invoke-static {v5, v6}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v7

    move v8, v3

    :cond_0
    :goto_0
    const/16 v9, 0x40

    const/16 v10, 0x20

    if-nez v3, :cond_13

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v11
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v11, :cond_1

    const/16 v12, 0x8

    if-eq v11, v12, :cond_10

    const/4 v13, 0x2

    const/16 v14, 0x10

    if-eq v11, v14, :cond_f

    const/16 v15, 0x18

    const/16 v16, 0x0

    if-eq v11, v15, :cond_a

    const/16 v13, 0x22

    if-eq v11, v13, :cond_7

    const/16 v12, 0x28

    if-eq v11, v12, :cond_6

    sget-object v12, Llyiahf/vczjk/nc7;->OooOOO:Llyiahf/vczjk/je4;

    const/16 v13, 0x32

    if-eq v11, v13, :cond_4

    const/16 v13, 0x3a

    if-eq v11, v13, :cond_2

    :try_start_1
    invoke-virtual {v0, v11, v7}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v9

    if-nez v9, :cond_0

    :cond_1
    move v3, v6

    goto :goto_0

    :cond_2
    and-int/lit8 v11, v8, 0x40

    if-eq v11, v9, :cond_3

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    iput-object v11, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    or-int/lit8 v8, v8, 0x40

    goto :goto_1

    :catchall_0
    move-exception v0

    goto/16 :goto_6

    :catch_0
    move-exception v0

    goto/16 :goto_4

    :catch_1
    move-exception v0

    goto/16 :goto_5

    :cond_3
    :goto_1
    iget-object v11, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-virtual {v0, v12, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v12

    invoke-interface {v11, v12}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_4
    and-int/lit8 v11, v8, 0x20

    if-eq v11, v10, :cond_5

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    iput-object v11, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    or-int/lit8 v8, v8, 0x20

    :cond_5
    iget-object v11, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-virtual {v0, v12, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v12

    invoke-interface {v11, v12}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_6
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    or-int/2addr v11, v14

    iput v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v11

    iput v11, v1, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    goto :goto_0

    :cond_7
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    and-int/2addr v11, v12

    if-ne v11, v12, :cond_8

    iget-object v11, v1, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v11}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v16

    :cond_8
    move-object/from16 v11, v16

    sget-object v13, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0, v13, v2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/hd7;

    iput-object v13, v1, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    if-eqz v11, :cond_9

    invoke-virtual {v11, v13}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v11}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v11

    iput-object v11, v1, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    :cond_9
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    or-int/2addr v11, v12

    iput v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    goto/16 :goto_0

    :cond_a
    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v12

    if-eqz v12, :cond_d

    if-eq v12, v6, :cond_c

    if-eq v12, v13, :cond_b

    :goto_2
    move-object/from16 v13, v16

    goto :goto_3

    :cond_b
    sget-object v16, Llyiahf/vczjk/mc7;->OooOOOO:Llyiahf/vczjk/mc7;

    goto :goto_2

    :cond_c
    sget-object v16, Llyiahf/vczjk/mc7;->OooOOO:Llyiahf/vczjk/mc7;

    goto :goto_2

    :cond_d
    move-object v13, v4

    :goto_3
    if-nez v13, :cond_e

    invoke-virtual {v7, v11}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v7, v12}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto/16 :goto_0

    :cond_e
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    or-int/lit8 v11, v11, 0x4

    iput v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    iput-object v13, v1, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    goto/16 :goto_0

    :cond_f
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    or-int/2addr v11, v13

    iput v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v11

    iput v11, v1, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    goto/16 :goto_0

    :cond_10
    iget v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    or-int/2addr v11, v6

    iput v11, v1, Llyiahf/vczjk/nc7;->bitField0_:I

    invoke-virtual {v0}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v11

    iput v11, v1, Llyiahf/vczjk/nc7;->flags_:I
    :try_end_1
    .catch Llyiahf/vczjk/i44; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto/16 :goto_0

    :goto_4
    :try_start_2
    new-instance v2, Llyiahf/vczjk/i44;

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v2

    :goto_5
    invoke-virtual {v0, v1}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :goto_6
    and-int/lit8 v2, v8, 0x20

    if-ne v2, v10, :cond_11

    iget-object v2, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    :cond_11
    and-int/lit8 v2, v8, 0x40

    if-ne v2, v9, :cond_12

    iget-object v2, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    :cond_12
    :try_start_3
    invoke-virtual {v7}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :catch_2
    invoke-virtual {v5}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_7

    :catchall_1
    move-exception v0

    invoke-virtual {v5}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    throw v0

    :goto_7
    throw v0

    :cond_13
    and-int/lit8 v0, v8, 0x20

    if-ne v0, v10, :cond_14

    iget-object v0, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    :cond_14
    and-int/lit8 v0, v8, 0x40

    if-ne v0, v9, :cond_15

    iget-object v0, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    :cond_15
    :try_start_4
    invoke-virtual {v7}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    invoke-virtual {v5}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception v0

    invoke-virtual {v5}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    throw v0

    :catch_3
    invoke-virtual {v5}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/lc7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/nc7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO(Llyiahf/vczjk/nc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/nc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/nc7;->flags_:I

    return-void
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/nc7;Llyiahf/vczjk/mc7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/nc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/nc7;Llyiahf/vczjk/hd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/nc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    return-void
.end method

.method public static synthetic OooOO0(Llyiahf/vczjk/nc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOO0O(Llyiahf/vczjk/nc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOO0o(Llyiahf/vczjk/nc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/nc7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method

.method public static synthetic OooOOO0(Llyiahf/vczjk/nc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/nc7;->getSerializedSize()I

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    iget v0, p0, Llyiahf/vczjk/nc7;->flags_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_1
    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    invoke-virtual {v0}, Llyiahf/vczjk/mc7;->getNumber()I

    move-result v0

    const/4 v2, 0x3

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_2
    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v2, 0x8

    and-int/2addr v0, v2

    if-ne v0, v2, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_3
    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_4

    const/4 v0, 0x5

    iget v1, p0, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_4
    const/4 v0, 0x0

    move v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pi5;

    const/4 v3, 0x6

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_5
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/4 v2, 0x7

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOOOO()Llyiahf/vczjk/mc7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    return-object v0
.end method

.method public final OooOOOo()Llyiahf/vczjk/hd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    return-object v0
.end method

.method public final OooOOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    return v0
.end method

.method public final OooOOo0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    return v0
.end method

.method public final OooOOoo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0O()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0o()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getFlags()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/nc7;->flags_:I

    return v0
.end method

.method public final getSerializedSize()I
    .locals 5

    iget v0, p0, Llyiahf/vczjk/nc7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/nc7;->flags_:I

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget v1, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v3, 0x2

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_2

    iget v1, p0, Llyiahf/vczjk/nc7;->valueParameterReference_:I

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_2
    iget v1, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/4 v3, 0x4

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/nc7;->constantValue_:Llyiahf/vczjk/mc7;

    invoke-virtual {v1}, Llyiahf/vczjk/mc7;->getNumber()I

    move-result v1

    const/4 v4, 0x3

    invoke-static {v4, v1}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_3
    iget v1, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v4, 0x8

    and-int/2addr v1, v4

    if-ne v1, v4, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    :cond_4
    iget v1, p0, Llyiahf/vczjk/nc7;->bitField0_:I

    const/16 v3, 0x10

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_5

    const/4 v1, 0x5

    iget v3, p0, Llyiahf/vczjk/nc7;->isInstanceTypeId_:I

    invoke-static {v1, v3}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_5
    move v1, v2

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v1, v3, :cond_6

    iget-object v3, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x6

    invoke-static {v4, v3}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v3

    add-int/2addr v0, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_6
    :goto_2
    iget-object v1, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v2, v1, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/4 v3, 0x7

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_7
    iget-object v1, p0, Llyiahf/vczjk/nc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/nc7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/nc7;->OooOo0()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/nc7;->isInstanceType_:Llyiahf/vczjk/hd7;

    invoke-virtual {v0}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    return v2

    :cond_2
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_4

    iget-object v3, p0, Llyiahf/vczjk/nc7;->andArgument_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/nc7;

    invoke-virtual {v3}, Llyiahf/vczjk/nc7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    return v2

    :cond_3
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_4
    move v0, v2

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_6

    iget-object v3, p0, Llyiahf/vczjk/nc7;->orArgument_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/nc7;

    invoke-virtual {v3}, Llyiahf/vczjk/nc7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_5

    iput-byte v2, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    return v2

    :cond_5
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_6
    iput-byte v1, p0, Llyiahf/vczjk/nc7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/lc7;->OooO0oO()Llyiahf/vczjk/lc7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/lc7;->OooO0oO()Llyiahf/vczjk/lc7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/lc7;->OooO0oo(Llyiahf/vczjk/nc7;)V

    return-object v0
.end method
