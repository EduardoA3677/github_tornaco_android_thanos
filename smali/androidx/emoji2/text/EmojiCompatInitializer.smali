.class public Landroidx/emoji2/text/EmojiCompatInitializer;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lz3;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Llyiahf/vczjk/lz3;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/List;
    .locals 1

    const-class v0, Landroidx/lifecycle/ProcessLifecycleInitializer;

    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0(Landroid/content/Context;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/pa3;

    new-instance v1, Llyiahf/vczjk/ra0;

    const/4 v2, 0x1

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/ra0;-><init>(Landroid/content/Context;I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/ol2;-><init>(Llyiahf/vczjk/ql2;)V

    const/4 v1, 0x1

    iput v1, v0, Llyiahf/vczjk/ol2;->OooO00o:I

    sget-object v1, Llyiahf/vczjk/rl2;->OooOO0O:Llyiahf/vczjk/rl2;

    if-nez v1, :cond_1

    sget-object v1, Llyiahf/vczjk/rl2;->OooOO0:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    sget-object v2, Llyiahf/vczjk/rl2;->OooOO0O:Llyiahf/vczjk/rl2;

    if-nez v2, :cond_0

    new-instance v2, Llyiahf/vczjk/rl2;

    invoke-direct {v2, v0}, Llyiahf/vczjk/rl2;-><init>(Llyiahf/vczjk/pa3;)V

    sput-object v2, Llyiahf/vczjk/rl2;->OooOO0O:Llyiahf/vczjk/rl2;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v1

    goto :goto_2

    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1

    :cond_1
    :goto_2
    invoke-static {p1}, Llyiahf/vczjk/uqa;->OooOOo(Landroid/content/Context;)Llyiahf/vczjk/uqa;

    move-result-object p1

    const-class v0, Landroidx/lifecycle/ProcessLifecycleInitializer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/uqa;->OooOOo:Ljava/lang/Object;

    monitor-enter v1

    :try_start_1
    iget-object v2, p1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashMap;

    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_2

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/uqa;->OooOOOO(Ljava/lang/Class;Ljava/util/HashSet;)Ljava/lang/Object;

    move-result-object v2

    goto :goto_3

    :catchall_1
    move-exception p1

    goto :goto_4

    :cond_2
    :goto_3
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    check-cast v2, Llyiahf/vczjk/uy4;

    invoke-interface {v2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/sl2;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/sl2;-><init>(Landroidx/emoji2/text/EmojiCompatInitializer;Llyiahf/vczjk/ky4;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :goto_4
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method
