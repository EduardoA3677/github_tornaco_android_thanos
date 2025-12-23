.class public final Llyiahf/vczjk/cd7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/cd7;


# instance fields
.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private string_:Llyiahf/vczjk/tw4;

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x15

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/cd7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/cd7;

    invoke-direct {v0}, Llyiahf/vczjk/cd7;-><init>()V

    sput-object v0, Llyiahf/vczjk/cd7;->OooOOO0:Llyiahf/vczjk/cd7;

    sget-object v1, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v1, v0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/cd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/cd7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dc7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/cd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/cd7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;)V
    .locals 7

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/cd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/cd7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v0, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    new-instance v0, Llyiahf/vczjk/hm0;

    invoke-direct {v0}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v2

    const/4 v3, 0x0

    move v4, v3

    :cond_0
    :goto_0
    if-nez v3, :cond_5

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v5

    if-eqz v5, :cond_1

    const/16 v6, 0xa

    if-eq v5, v6, :cond_2

    invoke-virtual {p1, v5, v2}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v5

    if-nez v5, :cond_0

    :cond_1
    move v3, v1

    goto :goto_0

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooO0o0()Llyiahf/vczjk/h25;

    move-result-object v5

    if-eq v4, v1, :cond_3

    new-instance v6, Llyiahf/vczjk/sw4;

    invoke-direct {v6}, Llyiahf/vczjk/sw4;-><init>()V

    iput-object v6, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    move v4, v1

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
    iget-object v6, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v6, v5}, Llyiahf/vczjk/tw4;->OooO0Oo(Llyiahf/vczjk/h25;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :goto_2
    :try_start_1
    new-instance v3, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v3, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v3

    :goto_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_4
    if-ne v4, v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v1}, Llyiahf/vczjk/tw4;->getUnmodifiableView()Llyiahf/vczjk/g9a;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    :cond_4
    :try_start_2
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_1
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    throw p1

    :cond_5
    if-ne v4, v1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {p1}, Llyiahf/vczjk/tw4;->getUnmodifiableView()Llyiahf/vczjk/g9a;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    :cond_6
    :try_start_3
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :catch_3
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/tw4;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    return-object p0
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/cd7;Llyiahf/vczjk/tw4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/cd7;->getSerializedSize()I

    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v1, v0}, Llyiahf/vczjk/tw4;->getByteString(I)Llyiahf/vczjk/im0;

    move-result-object v1

    const/4 v2, 0x2

    const/4 v3, 0x1

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/n11;->Oooo0o0(II)V

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooO0oO(I)Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    return-object p1
.end method

.method public final getSerializedSize()I
    .locals 4

    iget v0, p0, Llyiahf/vczjk/cd7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    const/4 v0, 0x0

    move v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-ge v0, v2, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v2, v0}, Llyiahf/vczjk/tw4;->getByteString(I)Llyiahf/vczjk/im0;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/im0;->size()I

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/n11;->OooO(I)I

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/im0;->size()I

    move-result v2

    add-int/2addr v2, v3

    add-int/2addr v1, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/cd7;->string_:Llyiahf/vczjk/tw4;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    add-int/2addr v0, v1

    iget-object v1, p0, Llyiahf/vczjk/cd7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/cd7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 2

    iget-byte v0, p0, Llyiahf/vczjk/cd7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    if-nez v0, :cond_1

    const/4 v0, 0x0

    return v0

    :cond_1
    iput-byte v1, p0, Llyiahf/vczjk/cd7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 2

    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 2

    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    return-object v0
.end method
