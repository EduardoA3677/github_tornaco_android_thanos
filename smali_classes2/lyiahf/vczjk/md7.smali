.class public final Llyiahf/vczjk/md7;
.super Llyiahf/vczjk/sg3;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/md7;


# instance fields
.field private bitField0_:I

.field private id_:I

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private name_:I

.field private reified_:Z

.field private final unknownFields:Llyiahf/vczjk/im0;

.field private upperBoundIdMemoizedSerializedSize:I

.field private upperBoundId_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private upperBound_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/hd7;",
            ">;"
        }
    .end annotation
.end field

.field private variance_:Llyiahf/vczjk/ld7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/md7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/md7;

    invoke-direct {v0}, Llyiahf/vczjk/md7;-><init>()V

    sput-object v0, Llyiahf/vczjk/md7;->OooOOO0:Llyiahf/vczjk/md7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/md7;->id_:I

    iput v1, v0, Llyiahf/vczjk/md7;->name_:I

    iput-boolean v1, v0, Llyiahf/vczjk/md7;->reified_:Z

    sget-object v1, Llyiahf/vczjk/ld7;->OooOOOO:Llyiahf/vczjk/ld7;

    iput-object v1, v0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/md7;->upperBoundIdMemoizedSerializedSize:I

    iput-byte v0, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/md7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 13

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/md7;->upperBoundIdMemoizedSerializedSize:I

    iput-byte v0, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/md7;->memoizedSerializedSize:I

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/md7;->id_:I

    iput v0, p0, Llyiahf/vczjk/md7;->name_:I

    iput-boolean v0, p0, Llyiahf/vczjk/md7;->reified_:Z

    sget-object v1, Llyiahf/vczjk/ld7;->OooOOOO:Llyiahf/vczjk/ld7;

    iput-object v1, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v2, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    iput-object v2, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    new-instance v2, Llyiahf/vczjk/hm0;

    invoke-direct {v2}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v3, 0x1

    invoke-static {v2, v3}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v4

    move v5, v0

    move v6, v5

    :cond_0
    :goto_0
    const/16 v7, 0x10

    const/16 v8, 0x20

    if-nez v5, :cond_14

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v9

    if-eqz v9, :cond_1

    const/16 v10, 0x8

    if-eq v9, v10, :cond_11

    const/4 v11, 0x2

    if-eq v9, v7, :cond_10

    const/16 v12, 0x18

    if-eq v9, v12, :cond_e

    if-eq v9, v8, :cond_9

    const/16 v10, 0x2a

    if-eq v9, v10, :cond_7

    const/16 v10, 0x30

    if-eq v9, v10, :cond_5

    const/16 v10, 0x32

    if-eq v9, v10, :cond_2

    invoke-virtual {p0, p1, v4, p2, v9}, Llyiahf/vczjk/sg3;->OooOO0o(Llyiahf/vczjk/h11;Llyiahf/vczjk/n11;Llyiahf/vczjk/iu2;I)Z

    move-result v7

    if-nez v7, :cond_0

    :cond_1
    move v5, v3

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :catch_0
    move-exception p1

    goto/16 :goto_4

    :catch_1
    move-exception p1

    goto/16 :goto_5

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v9

    invoke-virtual {p1, v9}, Llyiahf/vczjk/h11;->OooO0Oo(I)I

    move-result v9

    and-int/lit8 v10, v6, 0x20

    if-eq v10, v8, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v10

    if-lez v10, :cond_3

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    iput-object v10, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    or-int/lit8 v6, v6, 0x20

    :cond_3
    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooO0O0()I

    move-result v10

    if-lez v10, :cond_4

    iget-object v10, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v11

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-interface {v10, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    invoke-virtual {p1, v9}, Llyiahf/vczjk/h11;->OooO0OO(I)V

    goto :goto_0

    :cond_5
    and-int/lit8 v9, v6, 0x20

    if-eq v9, v8, :cond_6

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    iput-object v9, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    or-int/lit8 v6, v6, 0x20

    :cond_6
    iget-object v9, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v10

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-interface {v9, v10}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_7
    and-int/lit8 v9, v6, 0x10

    if-eq v9, v7, :cond_8

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    iput-object v9, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    or-int/lit8 v6, v6, 0x10

    :cond_8
    iget-object v9, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    sget-object v10, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v10, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v10

    invoke-interface {v9, v10}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v12

    if-eqz v12, :cond_c

    if-eq v12, v3, :cond_b

    if-eq v12, v11, :cond_a

    const/4 v11, 0x0

    goto :goto_2

    :cond_a
    move-object v11, v1

    goto :goto_2

    :cond_b
    sget-object v11, Llyiahf/vczjk/ld7;->OooOOO:Llyiahf/vczjk/ld7;

    goto :goto_2

    :cond_c
    sget-object v11, Llyiahf/vczjk/ld7;->OooOOO0:Llyiahf/vczjk/ld7;

    :goto_2
    if-nez v11, :cond_d

    invoke-virtual {v4, v9}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v4, v12}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto/16 :goto_0

    :cond_d
    iget v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    or-int/2addr v9, v10

    iput v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    iput-object v11, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    goto/16 :goto_0

    :cond_e
    iget v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    or-int/lit8 v9, v9, 0x4

    iput v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0o()J

    move-result-wide v9

    const-wide/16 v11, 0x0

    cmp-long v9, v9, v11

    if-eqz v9, :cond_f

    move v9, v3

    goto :goto_3

    :cond_f
    move v9, v0

    :goto_3
    iput-boolean v9, p0, Llyiahf/vczjk/md7;->reified_:Z

    goto/16 :goto_0

    :cond_10
    iget v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    or-int/2addr v9, v11

    iput v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v9

    iput v9, p0, Llyiahf/vczjk/md7;->name_:I

    goto/16 :goto_0

    :cond_11
    iget v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    or-int/2addr v9, v3

    iput v9, p0, Llyiahf/vczjk/md7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v9

    iput v9, p0, Llyiahf/vczjk/md7;->id_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :goto_4
    :try_start_1
    new-instance p2, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p2

    :goto_5
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_6
    and-int/lit8 p2, v6, 0x10

    if-ne p2, v7, :cond_12

    iget-object p2, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    :cond_12
    and-int/lit8 p2, v6, 0x20

    if-ne p2, v8, :cond_13

    iget-object p2, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    :cond_13
    :try_start_2
    invoke-virtual {v4}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_7

    :catchall_1
    move-exception p1

    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_7
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    throw p1

    :cond_14
    and-int/lit8 p1, v6, 0x10

    if-ne p1, v7, :cond_15

    iget-object p1, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    :cond_15
    and-int/lit8 p1, v6, 0x20

    if-ne p1, v8, :cond_16

    iget-object p1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    :cond_16
    :try_start_3
    invoke-virtual {v4}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catch_3
    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_8

    :catchall_2
    move-exception p1

    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_8
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kd7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg3;-><init>(Llyiahf/vczjk/rg3;)V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/md7;->upperBoundIdMemoizedSerializedSize:I

    iput-byte v0, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/md7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/md7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/md7;->id_:I

    return-void
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/md7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/md7;->name_:I

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/md7;Z)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/md7;->reified_:Z

    return-void
.end method

.method public static synthetic OooOOo(Llyiahf/vczjk/md7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/md7;Llyiahf/vczjk/ld7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    return-void
.end method

.method public static synthetic OooOOoo(Llyiahf/vczjk/md7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOo0(Llyiahf/vczjk/md7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOo00(Llyiahf/vczjk/md7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOo0O(Llyiahf/vczjk/md7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOo0o(Llyiahf/vczjk/md7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/md7;->getSerializedSize()I

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/sg3;)V

    iget v1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget v1, p0, Llyiahf/vczjk/md7;->id_:I

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    iget v1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    iget v1, p0, Llyiahf/vczjk/md7;->name_:I

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_1
    iget v1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    const/4 v3, 0x0

    if-ne v1, v2, :cond_2

    iget-boolean v1, p0, Llyiahf/vczjk/md7;->reified_:Z

    const/4 v4, 0x3

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/n11;->Oooo0o0(II)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/n11;->OooOooo(I)V

    :cond_2
    iget v1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/16 v4, 0x8

    and-int/2addr v1, v4

    if-ne v1, v4, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    invoke-virtual {v1}, Llyiahf/vczjk/ld7;->getNumber()I

    move-result v1

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_3
    move v1, v3

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pi5;

    const/4 v4, 0x5

    invoke-virtual {p1, v4, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-lez v1, :cond_5

    const/16 v1, 0x32

    invoke-virtual {p1, v1}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    iget v1, p0, Llyiahf/vczjk/md7;->upperBoundIdMemoizedSerializedSize:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    :cond_5
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v3, v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/n11;->OooOoo0(I)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_6
    const/16 v1, 0x3e8

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n62;->o000OO(ILlyiahf/vczjk/n11;)V

    iget-object v0, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/md7;->id_:I

    return v0
.end method

.method public final OooOoO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/md7;->reified_:Z

    return v0
.end method

.method public final OooOoO0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/md7;->name_:I

    return v0
.end method

.method public final OooOoOO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOoo()Llyiahf/vczjk/ld7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    return-object v0
.end method

.method public final OooOoo0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOooO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOooo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v1, 0x2

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

    iget v0, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v1, 0x4

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

    iget v0, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getDefaultInstanceForType()Llyiahf/vczjk/pi5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/md7;->OooOOO0:Llyiahf/vczjk/md7;

    return-object v0
.end method

.method public final getSerializedSize()I
    .locals 5

    iget v0, p0, Llyiahf/vczjk/md7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/md7;->id_:I

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget v3, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v4, 0x2

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_2

    iget v3, p0, Llyiahf/vczjk/md7;->name_:I

    invoke-static {v4, v3}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v3

    add-int/2addr v0, v3

    :cond_2
    iget v3, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/4 v4, 0x4

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_3

    const/4 v3, 0x3

    invoke-static {v3}, Llyiahf/vczjk/n11;->OooOO0O(I)I

    move-result v3

    add-int/2addr v3, v1

    add-int/2addr v0, v3

    :cond_3
    iget v1, p0, Llyiahf/vczjk/md7;->bitField0_:I

    const/16 v3, 0x8

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/md7;->variance_:Llyiahf/vczjk/ld7;

    invoke-virtual {v1}, Llyiahf/vczjk/ld7;->getNumber()I

    move-result v1

    invoke-static {v4, v1}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_4
    move v1, v2

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v1, v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x5

    invoke-static {v4, v3}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v3

    add-int/2addr v0, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_5
    move v1, v2

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_6

    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Integer;

    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/n11;->OooO0o(I)I

    move-result v3

    add-int/2addr v1, v3

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_6
    add-int/2addr v0, v1

    iget-object v2, p0, Llyiahf/vczjk/md7;->upperBoundId_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_7

    add-int/lit8 v0, v0, 0x1

    invoke-static {v1}, Llyiahf/vczjk/n11;->OooO0o(I)I

    move-result v2

    add-int/2addr v0, v2

    :cond_7
    iput v1, p0, Llyiahf/vczjk/md7;->upperBoundIdMemoizedSerializedSize:I

    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o()I

    move-result v1

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/md7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v0}, Llyiahf/vczjk/im0;->size()I

    move-result v0

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/md7;->memoizedSerializedSize:I

    return v0
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/md7;->OooOooO()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    return v2

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/md7;->OooOooo()Z

    move-result v0

    if-nez v0, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    return v2

    :cond_3
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/md7;->upperBound_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hd7;

    invoke-virtual {v3}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_4

    iput-byte v2, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    return v2

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_6

    iput-byte v2, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    return v2

    :cond_6
    iput-byte v1, p0, Llyiahf/vczjk/md7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/kd7;->OooO0oo()Llyiahf/vczjk/kd7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/kd7;->OooO0oo()Llyiahf/vczjk/kd7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/kd7;->OooO(Llyiahf/vczjk/md7;)V

    return-object v0
.end method
