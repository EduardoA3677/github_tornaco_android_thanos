.class public final Llyiahf/vczjk/o11;
.super Llyiahf/vczjk/v34;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/oO0OOo0o;

.field public final OooOO0:Llyiahf/vczjk/fv3;

.field public final OooOO0O:Ljava/util/HashMap;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/fv3;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/o11;->OooOO0O:Ljava/util/HashMap;

    iput-object p1, p0, Llyiahf/vczjk/o11;->OooO:Llyiahf/vczjk/oO0OOo0o;

    iput-object p2, p0, Llyiahf/vczjk/o11;->OooOO0:Llyiahf/vczjk/fv3;

    return-void
.end method


# virtual methods
.method public final OooOo00(Llyiahf/vczjk/oz;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o11;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qb6;

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/o11;->OooO:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/qb6;->OooO00o:Llyiahf/vczjk/w42;

    invoke-virtual {p1}, Llyiahf/vczjk/k84;->OooO0Oo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final OooooO0(Llyiahf/vczjk/oz;)V
    .locals 6

    new-instance v4, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v0, 0x0

    invoke-direct {v4, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    new-instance v0, Llyiahf/vczjk/uqa;

    const/16 v1, 0x10

    const/4 v5, 0x0

    move-object v2, p0

    move-object v3, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/uqa;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    new-instance p1, Llyiahf/vczjk/jv3;

    iget-object v1, v2, Llyiahf/vczjk/o11;->OooO:Llyiahf/vczjk/oO0OOo0o;

    iget-object v1, v1, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v1, Landroid/content/Context;

    invoke-direct {p1, v1}, Llyiahf/vczjk/jv3;-><init>(Landroid/content/Context;)V

    iget-object v1, v3, Llyiahf/vczjk/oz;->OooO00o:Ljava/lang/String;

    iput-object v1, p1, Llyiahf/vczjk/jv3;->OooO0OO:Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/jv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/kv3;->OooO00o(Llyiahf/vczjk/kv3;)Llyiahf/vczjk/jv3;

    move-result-object p1

    iput-object v0, p1, Llyiahf/vczjk/jv3;->OooO0Oo:Llyiahf/vczjk/eg9;

    invoke-virtual {p1}, Llyiahf/vczjk/jv3;->OooO0O0()V

    invoke-virtual {p1}, Llyiahf/vczjk/jv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object p1

    iget-object v0, v2, Llyiahf/vczjk/o11;->OooOO0:Llyiahf/vczjk/fv3;

    check-cast v0, Llyiahf/vczjk/ii7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/di7;

    const/4 v5, 0x0

    invoke-direct {v1, v0, p1, v5}, Llyiahf/vczjk/di7;-><init>(Llyiahf/vczjk/ii7;Llyiahf/vczjk/kv3;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    iget-object v0, v0, Llyiahf/vczjk/ii7;->OooO0o0:Llyiahf/vczjk/to1;

    invoke-static {v0, v5, v1, p1}, Llyiahf/vczjk/os9;->OooOOOo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/xl3;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/w42;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/qb6;

    invoke-direct {v0, p1}, Llyiahf/vczjk/qb6;-><init>(Llyiahf/vczjk/w42;)V

    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x1

    invoke-virtual {v4, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    iget-object p1, v2, Llyiahf/vczjk/o11;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {p1, v3, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method
