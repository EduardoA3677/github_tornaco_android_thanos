.class public final Llyiahf/vczjk/vc7;
.super Llyiahf/vczjk/sg3;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/vc7;


# instance fields
.field private bitField0_:I

.field private class__:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/zb7;",
            ">;"
        }
    .end annotation
.end field

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private package_:Llyiahf/vczjk/tc7;

.field private qualifiedNames_:Llyiahf/vczjk/bd7;

.field private strings_:Llyiahf/vczjk/cd7;

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/vc7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/vc7;

    invoke-direct {v0}, Llyiahf/vczjk/vc7;-><init>()V

    sput-object v0, Llyiahf/vczjk/vc7;->OooOOO0:Llyiahf/vczjk/vc7;

    sget-object v1, Llyiahf/vczjk/cd7;->OooOOO0:Llyiahf/vczjk/cd7;

    iput-object v1, v0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    sget-object v1, Llyiahf/vczjk/bd7;->OooOOO0:Llyiahf/vczjk/bd7;

    iput-object v1, v0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    sget-object v1, Llyiahf/vczjk/tc7;->OooOOO0:Llyiahf/vczjk/tc7;

    iput-object v1, v0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/vc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 10

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/vc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/cd7;->OooOOO0:Llyiahf/vczjk/cd7;

    iput-object v0, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    sget-object v0, Llyiahf/vczjk/bd7;->OooOOO0:Llyiahf/vczjk/bd7;

    iput-object v0, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    sget-object v0, Llyiahf/vczjk/tc7;->OooOOO0:Llyiahf/vczjk/tc7;

    iput-object v0, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    new-instance v0, Llyiahf/vczjk/hm0;

    invoke-direct {v0}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v2

    const/4 v3, 0x0

    move v4, v3

    :cond_0
    :goto_0
    const/16 v5, 0x8

    if-nez v3, :cond_e

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v6

    if-eqz v6, :cond_1

    const/16 v7, 0xa

    const/4 v8, 0x0

    if-eq v6, v7, :cond_a

    const/16 v7, 0x12

    if-eq v6, v7, :cond_7

    const/16 v7, 0x1a

    if-eq v6, v7, :cond_4

    const/16 v7, 0x22

    if-eq v6, v7, :cond_2

    invoke-virtual {p0, p1, v2, p2, v6}, Llyiahf/vczjk/sg3;->OooOO0o(Llyiahf/vczjk/h11;Llyiahf/vczjk/n11;Llyiahf/vczjk/iu2;I)Z

    move-result v5

    if-nez v5, :cond_0

    :cond_1
    move v3, v1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :catch_0
    move-exception p1

    goto/16 :goto_1

    :catch_1
    move-exception p1

    goto/16 :goto_2

    :cond_2
    and-int/lit8 v6, v4, 0x8

    if-eq v6, v5, :cond_3

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    iput-object v6, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    move v4, v5

    :cond_3
    iget-object v6, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    sget-object v7, Llyiahf/vczjk/zb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v7, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v7

    invoke-interface {v6, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_4
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v7, 0x4

    and-int/2addr v6, v7

    if-ne v6, v7, :cond_5

    iget-object v6, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/sc7;->OooO0oo()Llyiahf/vczjk/sc7;

    move-result-object v8

    invoke-virtual {v8, v6}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    :cond_5
    sget-object v6, Llyiahf/vczjk/tc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v6, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tc7;

    iput-object v6, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    if-eqz v8, :cond_6

    invoke-virtual {v8, v6}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    invoke-virtual {v8}, Llyiahf/vczjk/sc7;->OooO0oO()Llyiahf/vczjk/tc7;

    move-result-object v6

    iput-object v6, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    :cond_6
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    or-int/2addr v6, v7

    iput v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    goto :goto_0

    :cond_7
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v7, 0x2

    and-int/2addr v6, v7

    if-ne v6, v7, :cond_8

    iget-object v6, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v8, Llyiahf/vczjk/dc7;

    const/4 v9, 0x1

    invoke-direct {v8, v9}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v9, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v9, v8, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v8, v6}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    :cond_8
    sget-object v6, Llyiahf/vczjk/bd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v6, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/bd7;

    iput-object v6, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    if-eqz v8, :cond_9

    invoke-virtual {v8, v6}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    invoke-virtual {v8}, Llyiahf/vczjk/dc7;->OooO0oO()Llyiahf/vczjk/bd7;

    move-result-object v6

    iput-object v6, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    :cond_9
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    or-int/2addr v6, v7

    iput v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    goto/16 :goto_0

    :cond_a
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    and-int/2addr v6, v1

    if-ne v6, v1, :cond_b

    iget-object v6, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v8, Llyiahf/vczjk/dc7;

    const/4 v7, 0x3

    invoke-direct {v8, v7}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v7, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v7, v8, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v8, v6}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    :cond_b
    sget-object v6, Llyiahf/vczjk/cd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v6, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/cd7;

    iput-object v6, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    if-eqz v8, :cond_c

    invoke-virtual {v8, v6}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    invoke-virtual {v8}, Llyiahf/vczjk/dc7;->OooO0oo()Llyiahf/vczjk/cd7;

    move-result-object v6

    iput-object v6, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    :cond_c
    iget v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    or-int/2addr v6, v1

    iput v6, p0, Llyiahf/vczjk/vc7;->bitField0_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :goto_1
    :try_start_1
    new-instance p2, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p2

    :goto_2
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_3
    and-int/lit8 p2, v4, 0x8

    if-ne p2, v5, :cond_d

    iget-object p2, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    :cond_d
    :try_start_2
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_4

    :catchall_1
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_4
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    throw p1

    :cond_e
    and-int/lit8 p1, v4, 0x8

    if-ne p1, v5, :cond_f

    iget-object p1, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    :cond_f
    :try_start_3
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catch_3
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_2
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uc7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg3;-><init>(Llyiahf/vczjk/rg3;)V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/vc7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/vc7;Llyiahf/vczjk/cd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    return-void
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/vc7;Llyiahf/vczjk/bd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/vc7;Llyiahf/vczjk/tc7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    return-void
.end method

.method public static synthetic OooOOo(Llyiahf/vczjk/vc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/vc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOoo(Llyiahf/vczjk/vc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOo00(Llyiahf/vczjk/vc7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/vc7;->getSerializedSize()I

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/sg3;)V

    iget v1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_0
    iget v1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_1
    iget v1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_2

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    invoke-virtual {p1, v1, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_2
    const/4 v1, 0x0

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v1, v3, :cond_3

    iget-object v3, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_3
    const/16 v1, 0xc8

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n62;->o000OO(ILlyiahf/vczjk/n11;)V

    iget-object v0, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOo()Llyiahf/vczjk/cd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    return-object v0
.end method

.method public final OooOo0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    return-object v0
.end method

.method public final OooOo0O()Llyiahf/vczjk/tc7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    return-object v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/bd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    return-object v0
.end method

.method public final OooOoO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoO0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoOO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getDefaultInstanceForType()Llyiahf/vczjk/pi5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/vc7;->OooOOO0:Llyiahf/vczjk/vc7;

    return-object v0
.end method

.method public final getSerializedSize()I
    .locals 5

    iget v0, p0, Llyiahf/vczjk/vc7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/vc7;->strings_:Llyiahf/vczjk/cd7;

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget v1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v3, 0x2

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    :cond_2
    iget v1, p0, Llyiahf/vczjk/vc7;->bitField0_:I

    const/4 v3, 0x4

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_3

    const/4 v1, 0x3

    iget-object v4, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    invoke-static {v1, v4}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    :cond_3
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v2, v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_4
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o()I

    move-result v1

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/vc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v0}, Llyiahf/vczjk/im0;->size()I

    move-result v0

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/vc7;->memoizedSerializedSize:I

    return v0
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/vc7;->OooOoO()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/vc7;->qualifiedNames_:Llyiahf/vczjk/bd7;

    invoke-virtual {v0}, Llyiahf/vczjk/bd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    return v2

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/vc7;->OooOoO0()Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/vc7;->package_:Llyiahf/vczjk/tc7;

    invoke-virtual {v0}, Llyiahf/vczjk/tc7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    return v2

    :cond_3
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/vc7;->class__:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zb7;

    invoke-virtual {v3}, Llyiahf/vczjk/zb7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_4

    iput-byte v2, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    return v2

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_6

    iput-byte v2, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    return v2

    :cond_6
    iput-byte v1, p0, Llyiahf/vczjk/vc7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/uc7;->OooO0oo()Llyiahf/vczjk/uc7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/uc7;->OooO0oo()Llyiahf/vczjk/uc7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/uc7;->OooO(Llyiahf/vczjk/vc7;)V

    return-object v0
.end method
