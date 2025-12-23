.class public final Llyiahf/vczjk/y58;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/x58;

.field public final OooOOO0:Ljava/lang/String;

.field public OooOOOO:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/x58;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y58;->OooOOO0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/y58;->OooOOO:Llyiahf/vczjk/x58;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    if-ne p2, v0, :cond_0

    const/4 p2, 0x0

    iput-boolean p2, p0, Llyiahf/vczjk/y58;->OooOOOO:Z

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    :cond_0
    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/ky4;Llyiahf/vczjk/e68;)V
    .locals 1

    const-string v0, "registry"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lifecycle"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/y58;->OooOOOO:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/y58;->OooOOOO:Z

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    iget-object p1, p0, Llyiahf/vczjk/y58;->OooOOO:Llyiahf/vczjk/x58;

    iget-object p1, p1, Llyiahf/vczjk/x58;->OooO0O0:Llyiahf/vczjk/mi;

    iget-object p1, p1, Llyiahf/vczjk/mi;->OooOOo0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/n61;

    iget-object v0, p0, Llyiahf/vczjk/y58;->OooOOO0:Ljava/lang/String;

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/e68;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/d68;)V

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Already attached to lifecycleOwner"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final close()V
    .locals 0

    return-void
.end method
