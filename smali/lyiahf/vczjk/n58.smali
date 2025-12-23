.class public final Llyiahf/vczjk/n58;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no7;


# instance fields
.field public OooOOO:Llyiahf/vczjk/t58;

.field public OooOOO0:Llyiahf/vczjk/k68;

.field public OooOOOO:Ljava/lang/String;

.field public OooOOOo:Ljava/lang/Object;

.field public OooOOo:Llyiahf/vczjk/s58;

.field public OooOOo0:[Ljava/lang/Object;

.field public final OooOOoo:Llyiahf/vczjk/m58;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k68;Llyiahf/vczjk/t58;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n58;->OooOOO0:Llyiahf/vczjk/k68;

    iput-object p2, p0, Llyiahf/vczjk/n58;->OooOOO:Llyiahf/vczjk/t58;

    iput-object p3, p0, Llyiahf/vczjk/n58;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/n58;->OooOOOo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/n58;->OooOOo0:[Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/m58;

    invoke-direct {p1, p0}, Llyiahf/vczjk/m58;-><init>(Llyiahf/vczjk/n58;)V

    iput-object p1, p0, Llyiahf/vczjk/n58;->OooOOoo:Llyiahf/vczjk/m58;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/ed5;

    invoke-virtual {v0}, Llyiahf/vczjk/ed5;->Oooo()V

    :cond_0
    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/ed5;

    invoke-virtual {v0}, Llyiahf/vczjk/ed5;->Oooo()V

    :cond_0
    return-void
.end method

.method public final OooO0OO()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/n58;->OooO0Oo()V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/n58;->OooOOO:Llyiahf/vczjk/t58;

    iget-object v1, p0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    if-nez v1, :cond_4

    if-eqz v0, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/n58;->OooOOoo:Llyiahf/vczjk/m58;

    invoke-virtual {v1}, Llyiahf/vczjk/m58;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-interface {v0, v2}, Llyiahf/vczjk/t58;->OooO00o(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_2

    new-instance v0, Ljava/lang/IllegalArgumentException;

    instance-of v1, v2, Llyiahf/vczjk/dw8;

    if-eqz v1, :cond_1

    check-cast v2, Llyiahf/vczjk/dw8;

    invoke-interface {v2}, Llyiahf/vczjk/dw8;->OooO0o()Llyiahf/vczjk/gw8;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/e86;->OooOOo0:Llyiahf/vczjk/e86;

    if-eq v1, v3, :cond_0

    invoke-interface {v2}, Llyiahf/vczjk/dw8;->OooO0o()Llyiahf/vczjk/gw8;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    if-eq v1, v3, :cond_0

    invoke-interface {v2}, Llyiahf/vczjk/dw8;->OooO0o()Llyiahf/vczjk/gw8;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/pp3;->OooOo00:Llyiahf/vczjk/pp3;

    if-eq v1, v3, :cond_0

    const-string v1, "If you use a custom SnapshotMutationPolicy for your MutableState you have to write a custom Saver"

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "MutableState containing "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " cannot be saved using the current SaveableStateRegistry. The default implementation only supports types which can be stored inside the Bundle. Please consider implementing a custom Saver for this class and pass it as a stateSaver parameter to rememberSaveable()."

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_1
    invoke-static {v2}, Llyiahf/vczjk/ht6;->OooOOo0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    :goto_0
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/n58;->OooOOOO:Ljava/lang/String;

    invoke-interface {v0, v2, v1}, Llyiahf/vczjk/t58;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/le3;)Llyiahf/vczjk/s58;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    :cond_3
    return-void

    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "entry("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ") is not null"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method
