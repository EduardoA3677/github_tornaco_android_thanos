.class public final Llyiahf/vczjk/fd7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/fd7;


# instance fields
.field private bitField0_:I

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private projection_:Llyiahf/vczjk/ed7;

.field private typeId_:I

.field private type_:Llyiahf/vczjk/hd7;

.field private final unknownFields:Llyiahf/vczjk/im0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x17

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/fd7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/fd7;

    invoke-direct {v0}, Llyiahf/vczjk/fd7;-><init>()V

    sput-object v0, Llyiahf/vczjk/fd7;->OooOOO0:Llyiahf/vczjk/fd7;

    sget-object v1, Llyiahf/vczjk/ed7;->OooOOOO:Llyiahf/vczjk/ed7;

    iput-object v1, v0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    sget-object v1, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v1, v0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/fd7;->typeId_:I

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/fd7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dd7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/fd7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 9

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/fd7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/ed7;->OooOOOO:Llyiahf/vczjk/ed7;

    iput-object v0, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    sget-object v1, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v1, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    const/4 v1, 0x0

    iput v1, p0, Llyiahf/vczjk/fd7;->typeId_:I

    new-instance v2, Llyiahf/vczjk/hm0;

    invoke-direct {v2}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v3, 0x1

    invoke-static {v2, v3}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v4

    :cond_0
    :goto_0
    if-nez v1, :cond_c

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v5

    if-eqz v5, :cond_1

    const/16 v6, 0x8

    const/4 v7, 0x0

    const/4 v8, 0x2

    if-eq v5, v6, :cond_6

    const/16 v6, 0x12

    if-eq v5, v6, :cond_3

    const/16 v6, 0x18

    if-eq v5, v6, :cond_2

    invoke-virtual {p1, v5, v4}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v5

    if-nez v5, :cond_0

    :cond_1
    move v1, v3

    goto :goto_0

    :cond_2
    iget v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    or-int/lit8 v5, v5, 0x4

    iput v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v5

    iput v5, p0, Llyiahf/vczjk/fd7;->typeId_:I

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :catch_0
    move-exception p1

    goto :goto_2

    :catch_1
    move-exception p1

    goto :goto_3

    :cond_3
    iget v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    and-int/2addr v5, v8

    if-ne v5, v8, :cond_4

    iget-object v5, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v5}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v7

    :cond_4
    sget-object v5, Llyiahf/vczjk/hd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v5, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/hd7;

    iput-object v5, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    if-eqz v7, :cond_5

    invoke-virtual {v7, v5}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v7}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v5

    iput-object v5, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    :cond_5
    iget v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    or-int/2addr v5, v8

    iput v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    goto :goto_0

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    if-eqz v6, :cond_a

    if-eq v6, v3, :cond_9

    if-eq v6, v8, :cond_8

    const/4 v8, 0x3

    if-eq v6, v8, :cond_7

    goto :goto_1

    :cond_7
    sget-object v7, Llyiahf/vczjk/ed7;->OooOOOo:Llyiahf/vczjk/ed7;

    goto :goto_1

    :cond_8
    move-object v7, v0

    goto :goto_1

    :cond_9
    sget-object v7, Llyiahf/vczjk/ed7;->OooOOO:Llyiahf/vczjk/ed7;

    goto :goto_1

    :cond_a
    sget-object v7, Llyiahf/vczjk/ed7;->OooOOO0:Llyiahf/vczjk/ed7;

    :goto_1
    if-nez v7, :cond_b

    invoke-virtual {v4, v5}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v4, v6}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto :goto_0

    :cond_b
    iget v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    or-int/2addr v5, v3

    iput v5, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    iput-object v7, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;
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
    :try_start_2
    invoke-virtual {v4}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_1
    move-exception p1

    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    throw p1

    :cond_c
    :try_start_3
    invoke-virtual {v4}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :catch_3
    invoke-virtual {v2}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/fd7;Llyiahf/vczjk/ed7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    return-void
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/fd7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/fd7;->typeId_:I

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/fd7;Llyiahf/vczjk/hd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/fd7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/fd7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/ed7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/fd7;->getSerializedSize()I

    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    invoke-virtual {v0}, Llyiahf/vczjk/ed7;->getNumber()I

    move-result v0

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_1
    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_2

    const/4 v0, 0x3

    iget v1, p0, Llyiahf/vczjk/fd7;->typeId_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOO0()Llyiahf/vczjk/hd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    return-object v0
.end method

.method public final OooOO0O()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fd7;->typeId_:I

    return v0
.end method

.method public final OooOO0o()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOO0()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getSerializedSize()I
    .locals 3

    iget v0, p0, Llyiahf/vczjk/fd7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/fd7;->projection_:Llyiahf/vczjk/ed7;

    invoke-virtual {v0}, Llyiahf/vczjk/ed7;->getNumber()I

    move-result v0

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    invoke-static {v2, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v0, v1

    :cond_2
    iget v1, p0, Llyiahf/vczjk/fd7;->bitField0_:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    const/4 v1, 0x3

    iget v2, p0, Llyiahf/vczjk/fd7;->typeId_:I

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/fd7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/fd7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 3

    iget-byte v0, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/fd7;->OooOOO0()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/fd7;->type_:Llyiahf/vczjk/hd7;

    invoke-virtual {v0}, Llyiahf/vczjk/hd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    return v2

    :cond_2
    iput-byte v1, p0, Llyiahf/vczjk/fd7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/dd7;->OooO0oO()Llyiahf/vczjk/dd7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/dd7;->OooO0oO()Llyiahf/vczjk/dd7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/dd7;->OooO0oo(Llyiahf/vczjk/fd7;)V

    return-object v0
.end method
