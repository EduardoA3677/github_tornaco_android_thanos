.class public final Llyiahf/vczjk/td7;
.super Llyiahf/vczjk/vg3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/td7;


# instance fields
.field private bitField0_:I

.field private errorCode_:I

.field private level_:Llyiahf/vczjk/rd7;

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private message_:I

.field private final unknownFields:Llyiahf/vczjk/im0;

.field private versionFull_:I

.field private versionKind_:Llyiahf/vczjk/sd7;

.field private version_:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x1c

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/td7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/td7;

    invoke-direct {v0}, Llyiahf/vczjk/td7;-><init>()V

    sput-object v0, Llyiahf/vczjk/td7;->OooOOO0:Llyiahf/vczjk/td7;

    const/4 v1, 0x0

    iput v1, v0, Llyiahf/vczjk/td7;->version_:I

    iput v1, v0, Llyiahf/vczjk/td7;->versionFull_:I

    sget-object v2, Llyiahf/vczjk/rd7;->OooOOO:Llyiahf/vczjk/rd7;

    iput-object v2, v0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    iput v1, v0, Llyiahf/vczjk/td7;->errorCode_:I

    iput v1, v0, Llyiahf/vczjk/td7;->message_:I

    sget-object v1, Llyiahf/vczjk/sd7;->OooOOO0:Llyiahf/vczjk/sd7;

    iput-object v1, v0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/td7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/td7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;)V
    .locals 12

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/td7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/td7;->memoizedSerializedSize:I

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/td7;->version_:I

    iput v0, p0, Llyiahf/vczjk/td7;->versionFull_:I

    sget-object v1, Llyiahf/vczjk/rd7;->OooOOO:Llyiahf/vczjk/rd7;

    iput-object v1, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    iput v0, p0, Llyiahf/vczjk/td7;->errorCode_:I

    iput v0, p0, Llyiahf/vczjk/td7;->message_:I

    sget-object v2, Llyiahf/vczjk/sd7;->OooOOO0:Llyiahf/vczjk/sd7;

    iput-object v2, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    new-instance v3, Llyiahf/vczjk/hm0;

    invoke-direct {v3}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v4, 0x1

    invoke-static {v3, v4}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v5

    :cond_0
    :goto_0
    if-nez v0, :cond_10

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v6

    if-eqz v6, :cond_1

    const/16 v7, 0x8

    if-eq v6, v7, :cond_f

    const/4 v8, 0x2

    const/16 v9, 0x10

    if-eq v6, v9, :cond_e

    const/16 v10, 0x18

    const/4 v11, 0x0

    if-eq v6, v10, :cond_9

    const/16 v10, 0x20

    if-eq v6, v10, :cond_8

    const/16 v7, 0x28

    if-eq v6, v7, :cond_7

    const/16 v7, 0x30

    if-eq v6, v7, :cond_2

    invoke-virtual {p1, v6, v5}, Llyiahf/vczjk/h11;->OooOOo0(ILlyiahf/vczjk/n11;)Z

    move-result v6

    if-nez v6, :cond_0

    :cond_1
    move v0, v4

    goto :goto_0

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v7

    if-eqz v7, :cond_5

    if-eq v7, v4, :cond_4

    if-eq v7, v8, :cond_3

    goto :goto_1

    :cond_3
    sget-object v11, Llyiahf/vczjk/sd7;->OooOOOO:Llyiahf/vczjk/sd7;

    goto :goto_1

    :cond_4
    sget-object v11, Llyiahf/vczjk/sd7;->OooOOO:Llyiahf/vczjk/sd7;

    goto :goto_1

    :cond_5
    move-object v11, v2

    :goto_1
    if-nez v11, :cond_6

    invoke-virtual {v5, v6}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_5

    :catch_0
    move-exception p1

    goto :goto_3

    :catch_1
    move-exception p1

    goto/16 :goto_4

    :cond_6
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/2addr v6, v10

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    iput-object v11, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    goto :goto_0

    :cond_7
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/2addr v6, v9

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/td7;->message_:I

    goto :goto_0

    :cond_8
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/2addr v6, v7

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/td7;->errorCode_:I

    goto :goto_0

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v7

    if-eqz v7, :cond_c

    if-eq v7, v4, :cond_b

    if-eq v7, v8, :cond_a

    goto :goto_2

    :cond_a
    sget-object v11, Llyiahf/vczjk/rd7;->OooOOOO:Llyiahf/vczjk/rd7;

    goto :goto_2

    :cond_b
    move-object v11, v1

    goto :goto_2

    :cond_c
    sget-object v11, Llyiahf/vczjk/rd7;->OooOOO0:Llyiahf/vczjk/rd7;

    :goto_2
    if-nez v11, :cond_d

    invoke-virtual {v5, v6}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    goto/16 :goto_0

    :cond_d
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/lit8 v6, v6, 0x4

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    iput-object v11, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    goto/16 :goto_0

    :cond_e
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/2addr v6, v8

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/td7;->versionFull_:I

    goto/16 :goto_0

    :cond_f
    iget v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    or-int/2addr v6, v4

    iput v6, p0, Llyiahf/vczjk/td7;->bitField0_:I

    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOO0O()I

    move-result v6

    iput v6, p0, Llyiahf/vczjk/td7;->version_:I
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :goto_3
    :try_start_1
    new-instance v0, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v0

    :goto_4
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_5
    :try_start_2
    invoke-virtual {v5}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_6

    :catchall_1
    move-exception p1

    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_6
    throw p1

    :cond_10
    :try_start_3
    invoke-virtual {v5}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :catch_3
    invoke-virtual {v3}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qd7;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/o00O0;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/td7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/td7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooO(Llyiahf/vczjk/td7;Llyiahf/vczjk/sd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/td7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/td7;->version_:I

    return-void
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/td7;Llyiahf/vczjk/rd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/td7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/td7;->versionFull_:I

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/td7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/td7;->errorCode_:I

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/td7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/td7;->message_:I

    return-void
.end method

.method public static synthetic OooOO0(Llyiahf/vczjk/td7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOO0O(Llyiahf/vczjk/td7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/td7;->getSerializedSize()I

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    iget v0, p0, Llyiahf/vczjk/td7;->version_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/td7;->versionFull_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_1
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    invoke-virtual {v0}, Llyiahf/vczjk/rd7;->getNumber()I

    move-result v0

    const/4 v2, 0x3

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_2
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v2, 0x8

    and-int/2addr v0, v2

    if-ne v0, v2, :cond_3

    iget v0, p0, Llyiahf/vczjk/td7;->errorCode_:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_3
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_4

    const/4 v0, 0x5

    iget v1, p0, Llyiahf/vczjk/td7;->message_:I

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/n11;->OooOoOO(II)V

    :cond_4
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    invoke-virtual {v0}, Llyiahf/vczjk/sd7;->getNumber()I

    move-result v0

    const/4 v1, 0x6

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/n11;->OooOoO(II)V

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOO0o()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/td7;->errorCode_:I

    return v0
.end method

.method public final OooOOO()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/td7;->message_:I

    return v0
.end method

.method public final OooOOO0()Llyiahf/vczjk/rd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    return-object v0
.end method

.method public final OooOOOO()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/td7;->version_:I

    return v0
.end method

.method public final OooOOOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/td7;->versionFull_:I

    return v0
.end method

.method public final OooOOo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v1, 0x8

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/sd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    return-object v0
.end method

.method public final OooOOoo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

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

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0O()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x2

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

    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v1, 0x20

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getSerializedSize()I
    .locals 4

    iget v0, p0, Llyiahf/vczjk/td7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/td7;->version_:I

    invoke-static {v1, v0}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_2

    iget v1, p0, Llyiahf/vczjk/td7;->versionFull_:I

    invoke-static {v2, v1}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_2
    iget v1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/td7;->level_:Llyiahf/vczjk/rd7;

    invoke-virtual {v1}, Llyiahf/vczjk/rd7;->getNumber()I

    move-result v1

    const/4 v3, 0x3

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_3
    iget v1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v3, 0x8

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_4

    iget v1, p0, Llyiahf/vczjk/td7;->errorCode_:I

    invoke-static {v2, v1}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_4
    iget v1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_5

    const/4 v1, 0x5

    iget v2, p0, Llyiahf/vczjk/td7;->message_:I

    invoke-static {v1, v2}, Llyiahf/vczjk/n11;->OooO0o0(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_5
    iget v1, p0, Llyiahf/vczjk/td7;->bitField0_:I

    const/16 v2, 0x20

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/td7;->versionKind_:Llyiahf/vczjk/sd7;

    invoke-virtual {v1}, Llyiahf/vczjk/sd7;->getNumber()I

    move-result v1

    const/4 v2, 0x6

    invoke-static {v2, v1}, Llyiahf/vczjk/n11;->OooO0Oo(II)I

    move-result v1

    add-int/2addr v0, v1

    :cond_6
    iget-object v1, p0, Llyiahf/vczjk/td7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/td7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 2

    iget-byte v0, p0, Llyiahf/vczjk/td7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    if-nez v0, :cond_1

    const/4 v0, 0x0

    return v0

    :cond_1
    iput-byte v1, p0, Llyiahf/vczjk/td7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/qd7;->OooO0oO()Llyiahf/vczjk/qd7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/qd7;->OooO0oO()Llyiahf/vczjk/qd7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/qd7;->OooO0oo(Llyiahf/vczjk/td7;)V

    return-object v0
.end method
