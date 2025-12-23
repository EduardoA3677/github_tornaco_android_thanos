.class public final Llyiahf/vczjk/lz1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/String;

.field public final OooO0O0:Llyiahf/vczjk/uz5;

.field public final OooO0OO:Llyiahf/vczjk/oe3;

.field public final OooO0Oo:Llyiahf/vczjk/xr1;

.field public volatile OooO0o:Llyiahf/vczjk/jz1;

.field public final OooO0o0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/uz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lz1;->OooO00o:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/lz1;->OooO0O0:Llyiahf/vczjk/uz5;

    iput-object p3, p0, Llyiahf/vczjk/lz1;->OooO0OO:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/lz1;->OooO0Oo:Llyiahf/vczjk/xr1;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lz1;->OooO0o0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/th4;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Landroid/content/Context;

    const-string v0, "thisRef"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "property"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/lz1;->OooO0o:Llyiahf/vczjk/jz1;

    if-nez p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/lz1;->OooO0o0:Ljava/lang/Object;

    monitor-enter p2

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/lz1;->OooO0o:Llyiahf/vczjk/jz1;

    if-nez v0, :cond_0

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/m96;

    sget-object v1, Llyiahf/vczjk/ez2;->OooO00o:Llyiahf/vczjk/we4;

    iget-object v2, p0, Llyiahf/vczjk/lz1;->OooO0O0:Llyiahf/vczjk/uz5;

    new-instance v3, Llyiahf/vczjk/kz1;

    invoke-direct {v3, p1, p0}, Llyiahf/vczjk/kz1;-><init>(Landroid/content/Context;Llyiahf/vczjk/lz1;)V

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/m96;-><init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/j96;Llyiahf/vczjk/le3;)V

    iget-object v1, p0, Llyiahf/vczjk/lz1;->OooO0OO:Llyiahf/vczjk/oe3;

    const-string v2, "applicationContext"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    iget-object v1, p0, Llyiahf/vczjk/lz1;->OooO0Oo:Llyiahf/vczjk/xr1;

    const-string v2, "migrations"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/pp3;

    const/16 v3, 0x14

    invoke-direct {v2, v3}, Llyiahf/vczjk/pp3;-><init>(I)V

    new-instance v3, Llyiahf/vczjk/rx1;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/rx1;-><init>(Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/jz1;

    invoke-direct {v3, v0, p1, v2, v1}, Llyiahf/vczjk/jz1;-><init>(Llyiahf/vczjk/m96;Ljava/util/List;Llyiahf/vczjk/pp3;Llyiahf/vczjk/xr1;)V

    iput-object v3, p0, Llyiahf/vczjk/lz1;->OooO0o:Llyiahf/vczjk/jz1;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/lz1;->OooO0o:Llyiahf/vczjk/jz1;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p2

    return-object p1

    :goto_1
    monitor-exit p2

    throw p1

    :cond_1
    return-object p2
.end method
