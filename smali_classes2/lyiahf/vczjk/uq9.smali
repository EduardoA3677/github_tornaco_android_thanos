.class public final Llyiahf/vczjk/uq9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mr1;


# instance fields
.field public final OooOOO:Ljava/lang/ThreadLocal;

.field public final OooOOO0:Llyiahf/vczjk/oz6;

.field public final OooOOOO:Llyiahf/vczjk/wq9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oz6;Ljava/lang/ThreadLocal;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uq9;->OooOOO0:Llyiahf/vczjk/oz6;

    iput-object p2, p0, Llyiahf/vczjk/uq9;->OooOOO:Ljava/lang/ThreadLocal;

    new-instance p1, Llyiahf/vczjk/wq9;

    invoke-direct {p1, p2}, Llyiahf/vczjk/wq9;-><init>(Ljava/lang/ThreadLocal;)V

    iput-object p1, p0, Llyiahf/vczjk/uq9;->OooOOOO:Llyiahf/vczjk/wq9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uq9;->OooOOO:Ljava/lang/ThreadLocal;

    invoke-virtual {v0, p1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/or1;)Ljava/lang/Object;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/uq9;->OooOOO:Ljava/lang/ThreadLocal;

    invoke-virtual {p1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/uq9;->OooOOO0:Llyiahf/vczjk/oz6;

    invoke-virtual {p1, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uq9;->OooOOOO:Llyiahf/vczjk/wq9;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wq9;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p0

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uq9;->OooOOOO:Llyiahf/vczjk/wq9;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wq9;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    return-object p1

    :cond_0
    return-object p0
.end method

.method public final getKey()Llyiahf/vczjk/nr1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uq9;->OooOOOO:Llyiahf/vczjk/wq9;

    return-object v0
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ThreadLocal(value="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/uq9;->OooOOO0:Llyiahf/vczjk/oz6;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", threadLocal = "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/uq9;->OooOOO:Ljava/lang/ThreadLocal;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
