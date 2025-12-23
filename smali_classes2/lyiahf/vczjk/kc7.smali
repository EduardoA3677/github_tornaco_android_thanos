.class public final Llyiahf/vczjk/kc7;
.super Llyiahf/vczjk/sg3;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/kc7;


# instance fields
.field private bitField0_:I

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private name_:I

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0xd

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/kc7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/kc7;

    invoke-direct {v0}, Llyiahf/vczjk/kc7;-><init>()V

    sput-object v0, Llyiahf/vczjk/kc7;->OooOOO0:Llyiahf/vczjk/kc7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/kc7;->name_:I

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/kc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 6

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/kc7;->memoizedSerializedSize:I

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/kc7;->name_:I

    new-instance v1, Llyiahf/vczjk/hm0;

    invoke-direct {v1}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v2, 0x1

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v3

    :cond_0
    :goto_0
    if-nez v0, :cond_3

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v4

    if-eqz v4, :cond_1

    const/16 v5, 0x8

    if-eq v4, v5, :cond_2

    invoke-virtual {p0, p1, v3, p2, v4}, Llyiahf/vczjk/sg3;->OooOO0o(Llyiahf/vczjk/h11;Llyiahf/vczjk/n11;Llyiahf/vczjk/iu2;I)Z

    move-result v4

    if-nez v4, :cond_0

    :cond_1
    move v0, v2

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :catch_0
    move-exception p1

    goto :goto_1

    :catch_1
    move-exception p1

    goto :goto_2

    :cond_2
    iget v4, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    or-int/2addr v4, v2

    iput v4, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v4

    iput v4, p0, Llyiahf/vczjk/kc7;->name_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

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
    :try_start_2
    invoke-virtual {v3}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_4

    :catchall_1
    move-exception p1

    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_4
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    throw p1

    :cond_3
    :try_start_3
    invoke-virtual {v3}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catch_3
    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_2
    move-exception p1

    invoke-virtual {v1}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/jc7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg3;-><init>(Llyiahf/vczjk/rg3;)V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/kc7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/kc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/kc7;->name_:I

    return-void
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/kc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/kc7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/kc7;->getSerializedSize()I

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/sg3;)V

    iget v1, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget v1, p0, Llyiahf/vczjk/kc7;->name_:I

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    const/16 v1, 0xc8

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n62;->o000OO(ILlyiahf/vczjk/n11;)V

    iget-object v0, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOOo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/kc7;->name_:I

    return v0
.end method

.method public final getDefaultInstanceForType()Llyiahf/vczjk/pi5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/kc7;->OooOOO0:Llyiahf/vczjk/kc7;

    return-object v0
.end method

.method public final getSerializedSize()I
    .locals 2

    iget v0, p0, Llyiahf/vczjk/kc7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/kc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/kc7;->name_:I

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o()I

    move-result v1

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/kc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v0}, Llyiahf/vczjk/im0;->size()I

    move-result v0

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/kc7;->memoizedSerializedSize:I

    return v0
.end method

.method public final isInitialized()Z
    .locals 3

    iget-byte v0, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    return v2

    :cond_2
    iput-byte v1, p0, Llyiahf/vczjk/kc7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    new-instance v0, Llyiahf/vczjk/jc7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    new-instance v0, Llyiahf/vczjk/jc7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/jc7;->OooO0oO(Llyiahf/vczjk/kc7;)V

    return-object v0
.end method
