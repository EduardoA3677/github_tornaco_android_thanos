.class public final Llyiahf/vczjk/je4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kp6;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget v0, Llyiahf/vczjk/iu2;->OooO0O0:I

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/je4;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/pi5;)V
    .locals 2

    if-eqz p0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/ri5;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/o00O0;

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/o00O0;

    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    :goto_0
    new-instance v1, Llyiahf/vczjk/i44;

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw v1

    :cond_1
    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/je4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ud7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ud7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_0
    new-instance p2, Llyiahf/vczjk/td7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/td7;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/pd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/pd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/nd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/nd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/md7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/md7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_4
    new-instance v0, Llyiahf/vczjk/jd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/jd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/fd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/fd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_6
    new-instance v0, Llyiahf/vczjk/hd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/hd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_7
    new-instance p2, Llyiahf/vczjk/cd7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/cd7;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_8
    new-instance p2, Llyiahf/vczjk/ad7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/ad7;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_9
    new-instance v0, Llyiahf/vczjk/bd7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/bd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_a
    new-instance v0, Llyiahf/vczjk/xc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/xc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_b
    new-instance v0, Llyiahf/vczjk/vc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/vc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_c
    new-instance v0, Llyiahf/vczjk/tc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/tc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_d
    new-instance v0, Llyiahf/vczjk/pc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/pc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_e
    new-instance v0, Llyiahf/vczjk/nc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/nc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_f
    new-instance v0, Llyiahf/vczjk/kc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/kc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_10
    new-instance v0, Llyiahf/vczjk/ic7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ic7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_11
    new-instance v0, Llyiahf/vczjk/ec7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ec7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_12
    new-instance v0, Llyiahf/vczjk/cc7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/cc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_13
    new-instance p2, Llyiahf/vczjk/ac7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/ac7;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_14
    new-instance v0, Llyiahf/vczjk/zb7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/zb7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_15
    new-instance v0, Llyiahf/vczjk/tb7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/tb7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_16
    new-instance v0, Llyiahf/vczjk/ub7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ub7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_17
    new-instance v0, Llyiahf/vczjk/wb7;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/wb7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_18
    new-instance p2, Llyiahf/vczjk/se4;

    invoke-direct {p2, p1}, Llyiahf/vczjk/se4;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_19
    new-instance v0, Llyiahf/vczjk/te4;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/te4;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_1a
    new-instance v0, Llyiahf/vczjk/oe4;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/oe4;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V

    return-object v0

    :pswitch_1b
    new-instance p2, Llyiahf/vczjk/me4;

    invoke-direct {p2, p1}, Llyiahf/vczjk/me4;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    :pswitch_1c
    new-instance p2, Llyiahf/vczjk/le4;

    invoke-direct {p2, p1}, Llyiahf/vczjk/le4;-><init>(Llyiahf/vczjk/h11;)V

    return-object p2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Ljava/io/ByteArrayInputStream;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;
    .locals 5

    :try_start_0
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v0

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    const/4 p1, 0x0

    goto :goto_3

    :cond_0
    and-int/lit16 v2, v0, 0x80

    if-nez v2, :cond_1

    goto :goto_2

    :cond_1
    and-int/lit8 v0, v0, 0x7f

    const/4 v2, 0x7

    :goto_0
    const/16 v3, 0x20

    if-ge v2, v3, :cond_4

    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v3

    if-eq v3, v1, :cond_3

    and-int/lit8 v4, v3, 0x7f

    shl-int/2addr v4, v2

    or-int/2addr v0, v4

    and-int/lit16 v3, v3, 0x80

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    add-int/lit8 v2, v2, 0x7

    goto :goto_0

    :cond_3
    invoke-static {}, Llyiahf/vczjk/i44;->OooO0OO()Llyiahf/vczjk/i44;

    move-result-object p1

    throw p1

    :cond_4
    :goto_1
    const/16 v3, 0x40

    if-ge v2, v3, :cond_7

    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    if-eq v3, v1, :cond_6

    and-int/lit16 v3, v3, 0x80

    if-nez v3, :cond_5

    :goto_2
    new-instance v1, Llyiahf/vczjk/oo00o;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/oo00o;-><init>(Ljava/io/ByteArrayInputStream;I)V

    new-instance p1, Llyiahf/vczjk/h11;

    invoke-direct {p1, v1}, Llyiahf/vczjk/h11;-><init>(Ljava/io/InputStream;)V

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/kp6;->OooO00o(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/pi5;

    const/4 v0, 0x0

    :try_start_1
    invoke-virtual {p1, v0}, Llyiahf/vczjk/h11;->OooO00o(I)V
    :try_end_1
    .catch Llyiahf/vczjk/i44; {:try_start_1 .. :try_end_1} :catch_0

    move-object p1, p2

    :goto_3
    invoke-static {p1}, Llyiahf/vczjk/je4;->OooO0O0(Llyiahf/vczjk/pi5;)V

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1

    :cond_5
    add-int/lit8 v2, v2, 0x7

    goto :goto_1

    :cond_6
    :try_start_2
    invoke-static {}, Llyiahf/vczjk/i44;->OooO0OO()Llyiahf/vczjk/i44;

    move-result-object p1

    throw p1

    :cond_7
    new-instance p1, Llyiahf/vczjk/i44;

    const-string p2, "CodedInputStream encountered a malformed varint."

    invoke-direct {p1, p2}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    throw p1
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    :catch_1
    move-exception p1

    new-instance p2, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    throw p2
.end method
