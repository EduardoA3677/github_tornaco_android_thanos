.class public final Llyiahf/vczjk/tb7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/tb7;


# instance fields
.field private annotation_:Llyiahf/vczjk/wb7;

.field private arrayDimensionCount_:I

.field private arrayElement_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/tb7;",
            ">;"
        }
    .end annotation
.end field

.field private bitField0_:I

.field private classId_:I

.field private doubleValue_:D

.field private enumValueId_:I

.field private flags_:I

.field private floatValue_:F

.field private intValue_:J

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private stringValue_:I

.field private type_:Llyiahf/vczjk/sb7;

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tb7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/tb7;

    invoke-direct {v0}, Llyiahf/vczjk/tb7;-><init>()V

    sput-object v0, Llyiahf/vczjk/tb7;->OooOOO0:Llyiahf/vczjk/tb7;

    invoke-virtual {v0}, Llyiahf/vczjk/tb7;->Oooo0o()V

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tb7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 12

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tb7;->memoizedSerializedSize:I

    invoke-virtual {p0}, Llyiahf/vczjk/tb7;->Oooo0o()V

    new-instance v0, Llyiahf/vczjk/hm0;

    invoke-direct {v0}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v2

    const/4 v3, 0x0

    move v4, v3

    :cond_0
    :goto_0
    const/16 v5, 0x100

    if-nez v3, :cond_6

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v6

    sparse-switch v6, :sswitch_data_0

    invoke-virtual {p1, v6, v2}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v5

    if-nez v5, :cond_0

    :sswitch_0
    move v3, v1

    goto :goto_0

    :sswitch_1
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/2addr v6, v5

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :catch_0
    move-exception p1

    goto/16 :goto_2

    :catch_1
    move-exception p1

    goto/16 :goto_3

    :sswitch_2
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit16 v6, v6, 0x200

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->flags_:I

    goto :goto_0

    :sswitch_3
    and-int/lit16 v6, v4, 0x100

    if-eq v6, v5, :cond_1

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    iput-object v6, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    move v4, v5

    :cond_1
    iget-object v6, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    sget-object v7, Llyiahf/vczjk/tb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v7, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v7

    invoke-interface {v6, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :sswitch_4
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v7, 0x80

    and-int/2addr v6, v7

    if-ne v6, v7, :cond_2

    iget-object v6, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v8, Llyiahf/vczjk/vb7;

    const/4 v9, 0x0

    invoke-direct {v8, v9}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v9, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v9, v8, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v8, v6}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    goto :goto_1

    :cond_2
    const/4 v8, 0x0

    :goto_1
    sget-object v6, Llyiahf/vczjk/wb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v6, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/wb7;

    iput-object v6, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    if-eqz v8, :cond_3

    invoke-virtual {v8, v6}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    invoke-virtual {v8}, Llyiahf/vczjk/vb7;->OooO0o0()Llyiahf/vczjk/wb7;

    move-result-object v6

    iput-object v6, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    :cond_3
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/2addr v6, v7

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    goto/16 :goto_0

    :sswitch_5
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x40

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    goto/16 :goto_0

    :sswitch_6
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x20

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->classId_:I

    goto/16 :goto_0

    :sswitch_7
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x10

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    goto/16 :goto_0

    :sswitch_8
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x8

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0()J

    move-result-wide v6

    invoke-static {v6, v7}, Ljava/lang/Double;->longBitsToDouble(J)D

    move-result-wide v6

    iput-wide v6, p0, Llyiahf/vczjk/tb7;->doubleValue_:D

    goto/16 :goto_0

    :sswitch_9
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x4

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooO()I

    move-result v6

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    iput v6, p0, Llyiahf/vczjk/tb7;->floatValue_:F

    goto/16 :goto_0

    :sswitch_a
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/lit8 v6, v6, 0x2

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0o()J

    move-result-wide v6

    ushr-long v8, v6, v1

    const-wide/16 v10, 0x1

    and-long/2addr v6, v10

    neg-long v6, v6

    xor-long/2addr v6, v8

    iput-wide v6, p0, Llyiahf/vczjk/tb7;->intValue_:J

    goto/16 :goto_0

    :sswitch_b
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v7

    invoke-static {v7}, Llyiahf/vczjk/sb7;->OooO00o(I)Llyiahf/vczjk/sb7;

    move-result-object v8

    if-nez v8, :cond_4

    invoke-virtual {v2, v6}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v2, v7}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto/16 :goto_0

    :cond_4
    iget v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    or-int/2addr v6, v1

    iput v6, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    iput-object v8, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :goto_2
    :try_start_1
    new-instance p2, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p2

    :goto_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_4
    and-int/lit16 p2, v4, 0x100

    if-ne p2, v5, :cond_5

    iget-object p2, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    :cond_5
    :try_start_2
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_1
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    throw p1

    :cond_6
    and-int/lit16 p1, v4, 0x100

    if-ne p1, v5, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    :cond_7
    :try_start_3
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :catch_3
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_0
        0x8 -> :sswitch_b
        0x10 -> :sswitch_a
        0x1d -> :sswitch_9
        0x21 -> :sswitch_8
        0x28 -> :sswitch_7
        0x30 -> :sswitch_6
        0x38 -> :sswitch_5
        0x42 -> :sswitch_4
        0x4a -> :sswitch_3
        0x50 -> :sswitch_2
        0x58 -> :sswitch_1
    .end sparse-switch
.end method

.method public constructor <init>(Llyiahf/vczjk/rb7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tb7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->classId_:I

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/tb7;Llyiahf/vczjk/sb7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;

    return-void
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/tb7;F)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->floatValue_:F

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/tb7;J)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/tb7;->intValue_:J

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/tb7;D)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/tb7;->doubleValue_:D

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    return-void
.end method

.method public static synthetic OooOO0(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    return-void
.end method

.method public static synthetic OooOO0O(Llyiahf/vczjk/tb7;Llyiahf/vczjk/wb7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    return-void
.end method

.method public static synthetic OooOO0o(Llyiahf/vczjk/tb7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    return-void
.end method

.method public static synthetic OooOOO0(Llyiahf/vczjk/tb7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->flags_:I

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/tb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/tb7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/tb7;->getSerializedSize()I

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;

    invoke-virtual {v0}, Llyiahf/vczjk/sb7;->getNumber()I

    move-result v0

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v0, v2

    const/4 v3, 0x0

    if-ne v0, v2, :cond_1

    iget-wide v4, p0, Llyiahf/vczjk/tb7;->intValue_:J

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/n11;->Oooo0o0(II)V

    shl-long v6, v4, v1

    const/16 v0, 0x3f

    shr-long/2addr v4, v0

    xor-long/2addr v4, v6

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/n11;->Oooo0OO(J)V

    :cond_1
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v2, 0x4

    and-int/2addr v0, v2

    const/4 v4, 0x5

    if-ne v0, v2, :cond_2

    iget v0, p0, Llyiahf/vczjk/tb7;->floatValue_:F

    const/4 v5, 0x3

    invoke-virtual {p1, v5, v4}, Llyiahf/vczjk/n11;->Oooo0o0(II)V

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo00o(I)V

    :cond_2
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v5, 0x8

    and-int/2addr v0, v5

    if-ne v0, v5, :cond_3

    iget-wide v6, p0, Llyiahf/vczjk/tb7;->doubleValue_:D

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->Oooo0o0(II)V

    invoke-static {v6, v7}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    move-result-wide v0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->Oooo0(J)V

    :cond_3
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_4

    iget v0, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    invoke-virtual {p1, v4, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_4
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_5

    const/4 v0, 0x6

    iget v1, p0, Llyiahf/vczjk/tb7;->classId_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_5
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x40

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_6

    const/4 v0, 0x7

    iget v1, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_6
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x80

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    invoke-virtual {p1, v5, v0}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_7
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-ge v3, v0, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pi5;

    const/16 v1, 0x9

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_8
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x200

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_9

    const/16 v0, 0xa

    iget v1, p0, Llyiahf/vczjk/tb7;->flags_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_9
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_a

    const/16 v0, 0xb

    iget v1, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_a
    iget-object v0, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOOo()Llyiahf/vczjk/wb7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    return-object v0
.end method

.method public final OooOOoo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    return v0
.end method

.method public final OooOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    return v0
.end method

.method public final OooOo0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOo00(I)Llyiahf/vczjk/tb7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tb7;

    return-object p1
.end method

.method public final OooOo0O()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->classId_:I

    return v0
.end method

.method public final OooOo0o()D
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/tb7;->doubleValue_:D

    return-wide v0
.end method

.method public final OooOoO()J
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/tb7;->intValue_:J

    return-wide v0
.end method

.method public final OooOoO0()F
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->floatValue_:F

    return v0
.end method

.method public final OooOoOO()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    return v0
.end method

.method public final OooOoo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x80

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/sb7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;

    return-object v0
.end method

.method public final OooOooO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOooo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo000()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo00O()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x40

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo00o()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x200

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0O0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0OO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0o()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/sb7;->OooOOO0:Llyiahf/vczjk/sb7;

    iput-object v0, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/tb7;->intValue_:J

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/tb7;->floatValue_:F

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/tb7;->doubleValue_:D

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    iput v0, p0, Llyiahf/vczjk/tb7;->classId_:I

    iput v0, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    sget-object v1, Llyiahf/vczjk/wb7;->OooOOO0:Llyiahf/vczjk/wb7;

    iput-object v1, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    iput v0, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    iput v0, p0, Llyiahf/vczjk/tb7;->flags_:I

    return-void
.end method

.method public final Oooo0o0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getFlags()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tb7;->flags_:I

    return v0
.end method

.method public final getSerializedSize()I
    .locals 9

    iget v0, p0, Llyiahf/vczjk/tb7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/tb7;->type_:Llyiahf/vczjk/sb7;

    invoke-virtual {v0}, Llyiahf/vczjk/sb7;->getNumber()I

    move-result v0

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget v3, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v4, 0x2

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_2

    iget-wide v5, p0, Llyiahf/vczjk/tb7;->intValue_:J

    invoke-static {v4}, Llyiahf/vczjk/n11;->OooOO0O(I)I

    move-result v3

    shl-long v7, v5, v1

    const/16 v1, 0x3f

    shr-long v4, v5, v1

    xor-long/2addr v4, v7

    invoke-static {v4, v5}, Llyiahf/vczjk/n11;->OooOO0(J)I

    move-result v1

    add-int/2addr v1, v3

    add-int/2addr v0, v1

    :cond_2
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/4 v3, 0x4

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_3

    const/4 v1, 0x3

    invoke-static {v1}, Llyiahf/vczjk/n11;->OooOO0O(I)I

    move-result v1

    add-int/2addr v1, v3

    add-int/2addr v0, v1

    :cond_3
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v4, 0x8

    and-int/2addr v1, v4

    if-ne v1, v4, :cond_4

    invoke-static {v3}, Llyiahf/vczjk/n11;->OooOO0O(I)I

    move-result v1

    add-int/2addr v1, v4

    add-int/2addr v0, v1

    :cond_4
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v3, 0x10

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_5

    const/4 v1, 0x5

    iget v3, p0, Llyiahf/vczjk/tb7;->stringValue_:I

    invoke-static {v1, v3}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_5
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v3, 0x20

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_6

    const/4 v1, 0x6

    iget v3, p0, Llyiahf/vczjk/tb7;->classId_:I

    invoke-static {v1, v3}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_6
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v3, 0x40

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_7

    const/4 v1, 0x7

    iget v3, p0, Llyiahf/vczjk/tb7;->enumValueId_:I

    invoke-static {v1, v3}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_7
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v3, 0x80

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_8

    iget-object v1, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    invoke-static {v4, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    :cond_8
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v2, v1, :cond_9

    iget-object v1, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/16 v3, 0x9

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_9
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v2, 0x200

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_a

    const/16 v1, 0xa

    iget v2, p0, Llyiahf/vczjk/tb7;->flags_:I

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_a
    iget v1, p0, Llyiahf/vczjk/tb7;->bitField0_:I

    const/16 v2, 0x100

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_b

    const/16 v1, 0xb

    iget v2, p0, Llyiahf/vczjk/tb7;->arrayDimensionCount_:I

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_b
    iget-object v1, p0, Llyiahf/vczjk/tb7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/tb7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/tb7;->OooOoo()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/tb7;->annotation_:Llyiahf/vczjk/wb7;

    invoke-virtual {v0}, Llyiahf/vczjk/wb7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    return v2

    :cond_2
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/tb7;->arrayElement_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_4

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tb7;->OooOo00(I)Llyiahf/vczjk/tb7;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/tb7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    return v2

    :cond_3
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_4
    iput-byte v1, p0, Llyiahf/vczjk/tb7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/rb7;->OooO0oO()Llyiahf/vczjk/rb7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/rb7;->OooO0oO()Llyiahf/vczjk/rb7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/rb7;->OooO0oo(Llyiahf/vczjk/tb7;)V

    return-object v0
.end method
