.class public final Llyiahf/vczjk/wb7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/wb7;


# instance fields
.field private argument_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ub7;",
            ">;"
        }
    .end annotation
.end field

.field private bitField0_:I

.field private id_:I

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/wb7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/wb7;

    invoke-direct {v0}, Llyiahf/vczjk/wb7;-><init>()V

    sput-object v0, Llyiahf/vczjk/wb7;->OooOOO0:Llyiahf/vczjk/wb7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/wb7;->id_:I

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/wb7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 8

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/wb7;->memoizedSerializedSize:I

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/wb7;->id_:I

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/hm0;

    invoke-direct {v1}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v2, 0x1

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v3

    move v4, v0

    :cond_0
    :goto_0
    const/4 v5, 0x2

    if-nez v0, :cond_6

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v6

    if-eqz v6, :cond_1

    const/16 v7, 0x8

    if-eq v6, v7, :cond_4

    const/16 v7, 0x12

    if-eq v6, v7, :cond_2

    invoke-virtual {p1, v6, v3}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v5

    if-nez v5, :cond_0

    :cond_1
    move v0, v2

    goto :goto_0

    :cond_2
    and-int/lit8 v6, v4, 0x2

    if-eq v6, v5, :cond_3

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    iput-object v6, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    move v4, v5

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_4

    :catch_0
    move-exception p1

    goto :goto_2

    :catch_1
    move-exception p1

    goto :goto_3

    :cond_3
    :goto_1
    iget-object v6, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    sget-object v7, Llyiahf/vczjk/ub7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v7, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v7

    invoke-interface {v6, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_4
    iget v6, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    or-int/2addr v6, v2

    iput v6, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/wb7;->id_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

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
    and-int/lit8 p2, v4, 0x2

    if-ne p2, v5, :cond_5

    iget-object p2, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    :cond_5
    :try_start_2
    invoke-virtual {v3}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_1
    move-exception p1

    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    throw p1

    :cond_6
    and-int/lit8 p1, v4, 0x2

    if-ne p1, v5, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    :cond_7
    :try_start_3
    invoke-virtual {v3}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :catch_3
    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/vb7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/wb7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/wb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/wb7;->id_:I

    return-void
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/wb7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/wb7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/wb7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/wb7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    return v0
.end method

.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/wb7;->getSerializedSize()I

    iget v0, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    iget v0, p0, Llyiahf/vczjk/wb7;->id_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/4 v2, 0x2

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOO0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOO0O()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/wb7;->id_:I

    return v0
.end method

.method public final OooOO0o()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getSerializedSize()I
    .locals 4

    iget v0, p0, Llyiahf/vczjk/wb7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/wb7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/wb7;->id_:I

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v2, v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/4 v3, 0x2

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/wb7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/wb7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/wb7;->OooOO0o()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    return v2

    :cond_2
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_4

    iget-object v3, p0, Llyiahf/vczjk/wb7;->argument_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ub7;

    invoke-virtual {v3}, Llyiahf/vczjk/ub7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_3

    iput-byte v2, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    return v2

    :cond_3
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_4
    iput-byte v1, p0, Llyiahf/vczjk/wb7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 2

    new-instance v0, Llyiahf/vczjk/vb7;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 2

    new-instance v0, Llyiahf/vczjk/vb7;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    return-object v0
.end method
