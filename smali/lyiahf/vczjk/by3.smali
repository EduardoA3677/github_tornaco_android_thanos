.class public final Llyiahf/vczjk/by3;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _asNumeric:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 1

    const-class v0, Ljava/net/InetAddress;

    invoke-direct {p0, v0}, Llyiahf/vczjk/wt9;-><init>(Ljava/lang/Class;)V

    iput-boolean p1, p0, Llyiahf/vczjk/by3;->_asNumeric:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/p94;->OooO00o()Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p2, Llyiahf/vczjk/p94;->OooOOOo:Llyiahf/vczjk/p94;

    if-ne p1, p2, :cond_1

    :cond_0
    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    iget-boolean p2, p0, Llyiahf/vczjk/by3;->_asNumeric:Z

    if-eq p1, p2, :cond_2

    new-instance p2, Llyiahf/vczjk/by3;

    invoke-direct {p2, p1}, Llyiahf/vczjk/by3;-><init>(Z)V

    return-object p2

    :cond_2
    return-object p0
.end method

.method public final bridge synthetic OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, Ljava/net/InetAddress;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/by3;->OooOOOO(Ljava/net/InetAddress;Llyiahf/vczjk/u94;)V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    check-cast p1, Ljava/net/InetAddress;

    sget-object p3, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, p3}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object p3

    const-class v0, Ljava/net/InetAddress;

    iput-object v0, p3, Llyiahf/vczjk/rsa;->OooO0O0:Ljava/lang/Class;

    invoke-virtual {p4, p2, p3}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object p3

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/by3;->OooOOOO(Ljava/net/InetAddress;Llyiahf/vczjk/u94;)V

    invoke-virtual {p4, p2, p3}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooOOOO(Ljava/net/InetAddress;Llyiahf/vczjk/u94;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/by3;->_asNumeric:Z

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/net/InetAddress;->getHostAddress()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/net/InetAddress;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p1

    const/16 v0, 0x2f

    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    move-result v0

    if-ltz v0, :cond_2

    if-nez v0, :cond_1

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    invoke-virtual {p1, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p1

    :cond_2
    :goto_0
    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    return-void
.end method
