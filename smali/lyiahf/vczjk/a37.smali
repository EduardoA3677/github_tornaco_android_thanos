.class public final Llyiahf/vczjk/a37;
.super Llyiahf/vczjk/wg3;
.source "SourceFile"


# static fields
.field private static final DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

.field private static volatile PARSER:Llyiahf/vczjk/lp6; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/lp6;"
        }
    .end annotation
.end field

.field public static final PREFERENCES_FIELD_NUMBER:I = 0x1


# instance fields
.field private preferences_:Llyiahf/vczjk/qb5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qb5;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/a37;

    invoke-direct {v0}, Llyiahf/vczjk/a37;-><init>()V

    sput-object v0, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    const-class v1, Llyiahf/vczjk/a37;

    invoke-static {v1, v0}, Llyiahf/vczjk/wg3;->OooO(Ljava/lang/Class;Llyiahf/vczjk/wg3;)V

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/wg3;-><init>()V

    sget-object v0, Llyiahf/vczjk/qb5;->OooOOO0:Llyiahf/vczjk/qb5;

    iput-object v0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    return-void
.end method

.method public static OooOO0o(Llyiahf/vczjk/a37;)Llyiahf/vczjk/qb5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    invoke-virtual {v0}, Llyiahf/vczjk/qb5;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    invoke-virtual {v0}, Llyiahf/vczjk/qb5;->OooO0o0()Llyiahf/vczjk/qb5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    return-object p0
.end method

.method public static OooOOO()Llyiahf/vczjk/y27;
    .locals 2

    sget-object v0, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    const/4 v1, 0x5

    invoke-virtual {v0, v1}, Llyiahf/vczjk/a37;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pg3;

    check-cast v0, Llyiahf/vczjk/y27;

    return-object v0
.end method

.method public static OooOOOO(Ljava/io/InputStream;)Llyiahf/vczjk/a37;
    .locals 4

    sget-object v0, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    new-instance v1, Llyiahf/vczjk/g11;

    invoke-direct {v1, p0}, Llyiahf/vczjk/g11;-><init>(Ljava/io/InputStream;)V

    invoke-static {}, Llyiahf/vczjk/ju2;->OooO00o()Llyiahf/vczjk/ju2;

    move-result-object p0

    invoke-virtual {v0}, Llyiahf/vczjk/wg3;->OooO0oo()Llyiahf/vczjk/wg3;

    move-result-object v0

    :try_start_0
    sget-object v2, Llyiahf/vczjk/de7;->OooO0OO:Llyiahf/vczjk/de7;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/de7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/u88;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/i11;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/j11;

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    new-instance v3, Llyiahf/vczjk/j11;

    invoke-direct {v3, v1}, Llyiahf/vczjk/j11;-><init>(Llyiahf/vczjk/i11;)V

    :goto_0
    invoke-interface {v2, v0, v3, p0}, Llyiahf/vczjk/u88;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/j11;Llyiahf/vczjk/ju2;)V

    invoke-interface {v2, v0}, Llyiahf/vczjk/u88;->makeImmutable(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/j44; {:try_start_0 .. :try_end_0} :catch_2
    .catch Llyiahf/vczjk/w8a; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_3

    const/4 p0, 0x1

    invoke-static {v0, p0}, Llyiahf/vczjk/wg3;->OooO0o0(Llyiahf/vczjk/wg3;Z)Z

    move-result p0

    if-eqz p0, :cond_1

    check-cast v0, Llyiahf/vczjk/a37;

    return-object v0

    :cond_1
    new-instance p0, Llyiahf/vczjk/w8a;

    invoke-direct {p0}, Llyiahf/vczjk/w8a;-><init>()V

    new-instance v1, Llyiahf/vczjk/j44;

    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Llyiahf/vczjk/j44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/j44;->OooO0oO(Llyiahf/vczjk/wg3;)V

    throw v1

    :catch_0
    move-exception p0

    goto :goto_1

    :catch_1
    move-exception p0

    goto :goto_2

    :catch_2
    move-exception p0

    goto :goto_3

    :catch_3
    move-exception p0

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/j44;

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/j44;

    throw p0

    :cond_2
    throw p0

    :goto_1
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v1

    instance-of v1, v1, Llyiahf/vczjk/j44;

    if-eqz v1, :cond_3

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/j44;

    throw p0

    :cond_3
    new-instance v1, Llyiahf/vczjk/j44;

    invoke-direct {v1, p0}, Llyiahf/vczjk/j44;-><init>(Ljava/io/IOException;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/j44;->OooO0oO(Llyiahf/vczjk/wg3;)V

    throw v1

    :goto_2
    new-instance v1, Llyiahf/vczjk/j44;

    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Llyiahf/vczjk/j44;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/j44;->OooO0oO(Llyiahf/vczjk/wg3;)V

    throw v1

    :goto_3
    invoke-virtual {p0}, Llyiahf/vczjk/j44;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_4

    new-instance v1, Llyiahf/vczjk/j44;

    invoke-direct {v1, p0}, Llyiahf/vczjk/j44;-><init>(Ljava/io/IOException;)V

    move-object p0, v1

    :cond_4
    invoke-virtual {p0, v0}, Llyiahf/vczjk/j44;->OooO0oO(Llyiahf/vczjk/wg3;)V

    throw p0
.end method


# virtual methods
.method public final OooO0O0(I)Ljava/lang/Object;
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result p1

    packed-switch p1, :pswitch_data_0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1

    :pswitch_0
    sget-object p1, Llyiahf/vczjk/a37;->PARSER:Llyiahf/vczjk/lp6;

    if-nez p1, :cond_1

    const-class v0, Llyiahf/vczjk/a37;

    monitor-enter v0

    :try_start_0
    sget-object p1, Llyiahf/vczjk/a37;->PARSER:Llyiahf/vczjk/lp6;

    if-nez p1, :cond_0

    new-instance p1, Llyiahf/vczjk/qg3;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    sput-object p1, Llyiahf/vczjk/a37;->PARSER:Llyiahf/vczjk/lp6;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-object p1

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1

    :cond_1
    return-object p1

    :pswitch_1
    sget-object p1, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    return-object p1

    :pswitch_2
    new-instance p1, Llyiahf/vczjk/y27;

    sget-object v0, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    invoke-direct {p1, v0}, Llyiahf/vczjk/pg3;-><init>(Llyiahf/vczjk/wg3;)V

    return-object p1

    :pswitch_3
    new-instance p1, Llyiahf/vczjk/a37;

    invoke-direct {p1}, Llyiahf/vczjk/a37;-><init>()V

    return-object p1

    :pswitch_4
    const-string p1, "preferences_"

    sget-object v0, Llyiahf/vczjk/z27;->OooO00o:Llyiahf/vczjk/ob5;

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "\u0001\u0001\u0000\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u00012"

    sget-object v1, Llyiahf/vczjk/a37;->DEFAULT_INSTANCE:Llyiahf/vczjk/a37;

    new-instance v2, Llyiahf/vczjk/og7;

    invoke-direct {v2, v1, v0, p1}, Llyiahf/vczjk/og7;-><init>(Llyiahf/vczjk/wg3;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v2

    :pswitch_5
    const/4 p1, 0x0

    return-object p1

    :pswitch_6
    const/4 p1, 0x1

    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOOO0()Ljava/util/Map;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a37;->preferences_:Llyiahf/vczjk/qb5;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v0

    return-object v0
.end method
