.class public final Llyiahf/vczjk/fa6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;
.implements Llyiahf/vczjk/vp0;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/y96;

.field public final OooOOO0:Llyiahf/vczjk/ky4;

.field public OooOOOO:Llyiahf/vczjk/ga6;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ha6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ha6;Llyiahf/vczjk/ky4;Llyiahf/vczjk/y96;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-string v0, "onBackPressedCallback"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/fa6;->OooOOOo:Llyiahf/vczjk/ha6;

    iput-object p2, p0, Llyiahf/vczjk/fa6;->OooOOO0:Llyiahf/vczjk/ky4;

    iput-object p3, p0, Llyiahf/vczjk/fa6;->OooOOO:Llyiahf/vczjk/y96;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 8

    sget-object p1, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/fa6;->OooOOOo:Llyiahf/vczjk/ha6;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p1, "onBackPressedCallback"

    iget-object p2, p0, Llyiahf/vczjk/fa6;->OooOOO:Llyiahf/vczjk/y96;

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, v2, Llyiahf/vczjk/ha6;->OooO0O0:Llyiahf/vczjk/xx;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/ga6;

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/ga6;-><init>(Llyiahf/vczjk/ha6;Llyiahf/vczjk/y96;)V

    iget-object v0, p2, Llyiahf/vczjk/y96;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v2}, Llyiahf/vczjk/ha6;->OooO0o0()V

    new-instance v0, Llyiahf/vczjk/da;

    const-string v5, "updateEnabledCallbacks()V"

    const/4 v6, 0x0

    const/4 v1, 0x0

    const-class v3, Llyiahf/vczjk/ha6;

    const-string v4, "updateEnabledCallbacks"

    const/16 v7, 0x8

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    iput-object v0, p2, Llyiahf/vczjk/y96;->OooO0OO:Llyiahf/vczjk/wf3;

    iput-object p1, p0, Llyiahf/vczjk/fa6;->OooOOOO:Llyiahf/vczjk/ga6;

    return-void

    :cond_0
    sget-object p1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/fa6;->OooOOOO:Llyiahf/vczjk/ga6;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/ga6;->cancel()V

    return-void

    :cond_1
    sget-object p1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/fa6;->cancel()V

    :cond_2
    return-void
.end method

.method public final cancel()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fa6;->OooOOO0:Llyiahf/vczjk/ky4;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    iget-object v0, p0, Llyiahf/vczjk/fa6;->OooOOO:Llyiahf/vczjk/y96;

    iget-object v0, v0, Llyiahf/vczjk/y96;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    iget-object v0, p0, Llyiahf/vczjk/fa6;->OooOOOO:Llyiahf/vczjk/ga6;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ga6;->cancel()V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/fa6;->OooOOOO:Llyiahf/vczjk/ga6;

    return-void
.end method
